require 'eventmachine'
require 'date'

class StubsRequest

  attr_reader :headers, :body, :path, :method

  def initialize
    @state = :init
  end

  # adds data to the request, returns true if request is complete
  def complete?(str)
    if @state == :complete
     add_lines @body.byteslice(@content_length, @body.bytesize - @content_length)
    end
    add_lines str
    if @state == :body
      @content_length = @headers[:content_length].to_i ||= 0
      @state = :complete unless @body.bytesize < @content_length
    end
    @state == :complete
  end

  private

  def add_lines(str)
    str.each_line do |ln|
      if @state == :complete || @state == :init
        start = ln.chomp!.split(/\s+/)
        @method = start[0].downcase.to_sym
        @path = start[1]
        @headers = {}
        @body = ""
        @state = :headers
      elsif @state == :body
        @body << ln
      elsif ln.chomp!.empty?
        @state = :body
      else
        key, sep, val = ln.partition(/:\s+/)
        @headers[key.downcase!.gsub('-', '_').to_sym] = val
      end
    end
  end

end

class StubsReply
  attr_accessor :status, :headers, :body
  def initialize(status = 200)
    @status = status
    @headers = {}
    @body = ""
  end
  def to_s
    reply = "HTTP/1.0 #{@status} OK\r\n"
    headers[:connection] = "close"
    headers[:server] = "stub server"
    headers[:date] = DateTime.now.httpdate
    headers[:content_length] = @body.bytesize unless @body.empty?
    @headers.each do |k, v|
      reply << "#{k.to_s.gsub('_', '-')}: #{v}\r\n"
    end
    reply << "\r\n" << @body
  end
end


class StubServer

  PORT = 8089
  HOST = "127.0.0.1"

  module Server
    def receive_data(data)
      if @request.complete? data
        send_data @responder.call(@request, StubsReply.new).to_s
        close_connection_after_writing
      end
    end
    def responder=(blk)
      @responder = blk
      @request = StubsRequest.new
    end
  end

  def initialize(&blk)
    @sig = EM.start_server(HOST, PORT, Server) { |s| s.responder = blk }
    #puts "stub server started, #{@sig}"
    #@port = Socket.unpack_sockaddr_in(EM.get_sockname(@sig))[0]
  end

  def stop
    EM.stop_server @sig
  end

  def self.thread_request
    cthred = Thread.current
    sthred = Thread.new do
      EM.run do
        stubs = StubServer.new &@responder
        cthred.run
      end
    end
    Thread.stop
    yield
  ensure
    EM.stop
    sthred.join
  end

  def self.fiber_request
    EM.run do
      stubs = StubServer.new &@responder
      EM::Timer.new(2) { stubs.stop; EM.stop; fail "timed out" }
      Fiber.new { yield; stubs.stop; EM.stop }.resume
    end
  end

  def self.use_fiber=(use_fiber)
    @use_fiber = use_fiber
  end

  def self.request(&blk)
    @use_fiber ? fiber_request(&blk): thread_request(&blk)
  end

  def self.responder(&blk)
    @responder = blk
  end

  def self.url
    "http://#{HOST}:#{PORT}"
  end

end
