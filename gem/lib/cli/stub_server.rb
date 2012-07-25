#--
# Cloud Foundry 2012.02.03 Beta
# Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
#
# This product is licensed to you under the Apache License, Version 2.0 (the "License").
# You may not use this product except in compliance with the License.
#
# This product includes a number of subcomponents with
# separate copyright notices and license terms. Your use of these
# subcomponents is subject to the terms and conditions of the
# subcomponent's license, as noted in the LICENSE file.
#++

require 'eventmachine'
require 'date'
require 'logger'
require 'pp'

module Stub

#------------------------------------------------------------------------------
class Request
  attr_reader :headers, :body, :path, :method
  def initialize; @state = :init end

  # adds data to the request, returns true if request is complete
  def complete?(str)
    if @state == :complete
      # byteslice is available in ruby 1.9.3
      str = @content_length >= body.bytesize ? str : body.respond_to?(:byteslice) ?
          body.byteslice(@content_length, body.bytesize - @content_length) + str :
          body[@content_length..-1] + str
    end
    add_lines str
    if @state == :body
      @content_length = headers[:content_length].to_i ||= 0
      @state = :complete unless body.bytesize < @content_length
    end
    @state == :complete
  end

  private

  def add_lines(str)
    str.each_line do |ln|
      if @state == :complete || @state == :init
        start = ln.chomp!.split(/\s+/)
        @method, @path, @headers, @body = start[0].downcase.to_sym, start[1], {}, ""
        @state = :headers
      elsif @state == :body
        # TODO: figure out how to byteslice from ln to eos, append to @body, return
        @body << ln
      elsif (ln = ln.chomp).empty?
        @state = :body
      else
        key, sep, val = ln.partition(/:\s+/)
        @headers[key.downcase.gsub('-', '_').to_sym] = val
      end
    end
  end

end

#------------------------------------------------------------------------------
class Reply
  attr_accessor :status, :headers, :body
  def initialize(status = 200) @status, @headers, @body = status, {}, "" end
  def to_s
    reply = "HTTP/1.1 #{@status} OK\r\n"
    headers[:server] = "stub server"
    headers[:date] = DateTime.now.httpdate
    headers[:content_length] = body.bytesize
    headers.each { |k, v| reply << "#{k.to_s.gsub('_', '-')}: #{v}\r\n" }
    reply << "\r\n" << body
  end
  def json(info, status = nil)
    info = {message: info} unless info.respond_to? :each
    @status = status if status
    headers[:content_type] = "application/json"
    @body = info.to_json
    nil
  end
  def text(info, status = nil)
    @status = status if status
    headers[:content_type] = "text/plain"
    @body = info.pretty_inspect
    nil
  end
  #def html(info, status = nil)
    #@status = status if status
    #headers[:content_type] = "text/html"
    #@body = "<html><body>#{ERB::Util.html_escape(info.pretty_inspect)}</body></html>"
    #nil
  #end
end

#------------------------------------------------------------------------------
# request handler logic -- server is initialized with a class derived from this.
# there will be one instance of this object per connection.
class Base
  attr_accessor :request, :reply, :match, :server

  def self.route(http_methods, matcher, &handler)
    fail unless !EM.reactor_running? || EM.reactor_thread?
    matcher = Regexp.new("^#{Regexp.escape(matcher.to_s)}$") unless matcher.is_a? Regexp
    @routes ||= {}
    @route_number = (@route_number || 0) + 1
    route_name = "route_#{@route_number}".to_sym
    define_method(route_name, handler)
    [*http_methods].each do |m|
      m = m.to_sym
      @routes[m] ||= []
      i = @routes[m].index { |r| r[0].to_s.length < matcher.to_s.length }
      @routes[m].insert(i || -1, [matcher, route_name]) unless i && @routes[m][i][0] == matcher
    end
  end

  def self.find_route(request)
    fail unless EM.reactor_thread?
    if @routes && (rary = @routes[request.method])
      rary.each { |r; m| return [m, r[1]] if (m = r[0].match(request.path)) }
    end
    [nil, :default_route]
  end

  def initialize(server)
    @server, @request, @reply, @match = server, Request.new, Reply.new, nil
  end

  def process
    @match, handler = self.class.find_route(request)
    server.logger.debug "processing request to path #{request.path} for route #{@match ? @match.regexp : 'default'}"
    send handler
    reply.headers[:connection] ||= request.headers[:connection] if request.headers[:connection]
    server.logger.debug "replying to path #{request.path} with #{reply.body.length} bytes of #{reply.headers[:content_type]}"
  rescue Exception => e
    server.logger.debug "exception from route handler: #{e.message}"
    server.trace { e.backtrace }
    reply_in_kind e, 500
  end

  def reply_in_kind(info, status = nil)
    case request.headers[:accept]
    when /application\/json/ then reply.json(info, status)
    when /text\/html/ then reply.html(info, status)
    else reply.text(info, status)
    end
  end

  def default_route
    reply_in_kind("path not handled", 404)
  end

end

#------------------------------------------------------------------------------
module Connection
  attr_accessor :req_handler
  def unbind; req_handler.server.delete_connection(self) end

  def receive_data(data)
    #req_handler.server.logger.debug "got #{data.bytesize} bytes: #{data.inspect}"
    return unless req_handler.request.complete? data
    req_handler.process
    send_data req_handler.reply.to_s
    if req_handler.reply.headers[:connection] =~ /^close$/i || req_handler.server.status != :running
      close_connection_after_writing
    end
  rescue Exception => e
    req_handler.server.logger.debug "exception from receive_data: #{e.message}"
    req_handler.server.trace { e.backtrace }
    close_connection
  end
end

#--------------------------------------------------------------------------
class Server
  attr_reader :host, :port, :status, :logger
  attr_accessor :info
  def url; "http://#{@host}:#{@port}" end
  def trace(msg = nil, &blk); logger.trace(msg, &blk) if logger.respond_to?(:trace) end

  def initialize(req_handler, logger = Logger.new($stdout), info = nil)
    @req_handler, @logger, @info = req_handler, logger, info
    @connections, @status, @sig, @em_thread = [], :stopped, nil, nil
  end

  def start(hostname = "localhost", port = 0)
    raise ArgumentError, "attempt to start a server that's already running" unless @status == :stopped
    @host = hostname
    logger.debug "starting #{self.class} server #{@host}"
    EM.schedule do
      @sig = EM.start_server(@host, port, Connection) { |c| initialize_connection(c) }
      @port = Socket.unpack_sockaddr_in(EM.get_sockname(@sig))[0]
      logger.debug "#{self.class} server started at #{url}, signature #{@sig}"
    end
    @status = :running
    self
  end

  def run_on_thread(hostname = "localhost", port = 0)
    raise ArgumentError, "can't run on thread, EventMachine already running" if EM.reactor_running?
    logger.debug { "starting eventmachine on thread" }
    cthred = Thread.current
    @em_thread = Thread.new do
      begin
        EM.run { start(hostname, port); cthred.run }
        logger.debug "server thread done"
      rescue Exception => e
        logger.debug { "unhandled exception on stub server thread: #{e.message}" }
        trace { e.backtrace }
        raise
      end
    end
    Thread.stop
    logger.debug "running on thread"
    self
  end

  def run(hostname = "localhost", port = 0)
    raise ArgumentError, "can't run, EventMachine already running" if EM.reactor_running?
    @em_thread = Thread.current
    EM.run { start(hostname, port) }
    logger.debug "server and event machine done"
  end

  # if on reactor thread, start shutting down but return if connections still
  # in process, and let them disconnect when complete -- server is not really
  # done until it's status is stopped.
  # if not on reactor thread, wait until everything's cleaned up and stopped
  def stop
    logger.debug "stopping server"
    @status = :stopping
    EM.stop_server @sig
    done if @connections.empty?
    sleep 0.1 while @status != :stopped unless EM.reactor_thread?
  end

  def delete_connection(conn)
    logger.debug "deleting connection"
    fail unless EM.reactor_thread?
    @connections.delete(conn)
    done if @status != :running && @connections.empty?
  end

  private

  def done
    fail unless @connections.empty?
    EM.stop if @em_thread && EM.reactor_running?
    @connections, @status, @sig, @em_thread = [], :stopped, nil, nil
    sleep 0.1 unless EM.reactor_thread? # give EM a chance to stop
    logger.debug EM.reactor_running? ?
        "server done but EM still running" : "server really done"
  end

  def initialize_connection(conn)
    logger.debug "starting connection"
    fail unless EM.reactor_thread?
    @connections << conn
    conn.req_handler = @req_handler.new(self)
    conn.comm_inactivity_timeout = 30
  end

end

end
