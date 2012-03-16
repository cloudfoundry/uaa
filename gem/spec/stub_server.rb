class StubServer
  module Server
    def receive_data(data)
      send_data @response
      close_connection_after_writing
    end

    def response=(response)
      @response = response
    end
  end

  def initialize(response, port=8081)
    @sig = EventMachine::start_server("127.0.0.1", port, Server) { |s|
      s.response = response
    }
  end

  def stop
    EventMachine.stop_server @sig
  end
end
