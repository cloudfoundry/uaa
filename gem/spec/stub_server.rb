require "eventmachine"

class StubServer

  PORT = 8089
  HOST = "127.0.0.1"

  module Server
    def receive_data(data)
      send_data @responder.call(data)
      close_connection_after_writing
    end
    def responder=(blk)
      @responder = blk
    end
  end

  attr_reader :port

  def initialize(&blk)
    @sig = EM.start_server(HOST, PORT, Server) { |s| s.responder = blk }
    @port = Socket.unpack_sockaddr_in(EM.get_sockname(@sig))[0]
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

  def self.request(on_fiber, &blk)
    on_fiber ? fiber_request(&blk): thread_request(&blk)
  end

  def self.responder(&blk)
    @responder = blk
  end

  def self.url
    "http://#{HOST}:#{PORT}"
  end

end
