class EventDns < EventMachine::Connection
  @backend = nil
  attr_accessor :host, :port
  def initialize
    @backend = UseBackend.new(CONFIG[:backend])
    $logger.debug "Handling query via the #{CONFIG[:backend]} Backend."

    return unless CONFIG[:backend] == 'http'
    raise LoadError, "Please define a startup test" unless CONFIG[:startup_test].is_a? Array

    # Push a test query through our driver to make sure we have connectivity.
    domain = CONFIG[:startup_test][0] # example: 'pi.http.viadns.org'
    answer = CONFIG[:startup_test][1] # example: '3.14.159.26'

    test = Dnsruby::Message.new
    test.add_question(domain, Dnsruby::Types.A, Dnsruby::Classes.IN)
    test.question.each do |q|
      @backend.handle(q,test)
    end

    unless test.answer[0].name.to_s == domain &&  test.answer[0].address.to_s == answer
      raise LoadError, "Test query for #{domain} failed."
    end

    # Write our PID to a file.
    File.open(CONFIG[:pid_file], 'w') {|f| f.write(Process.pid) }

  end
  
  def new_connection
    # http://nhw.pl/wp/2007/12/07/eventmachine-how-to-get-clients-ip-address
    host = get_peername[2,6].unpack("nC4")
    @port = host.shift
    @host = host.join(".")
    
    $logger.info "Incoming packet from: #{client_info}"
  end
  
  def client_info
    host+":"+port.to_s
  end
  
  def receive_data(data)
    new_connection
    
    return unless data.size > 0

    begin
      packet = Dnsruby::Message.decode(data)
    rescue Exception => e
      $logger.error "Error decoding packet: #{e.inspect}"
      return
    end
    
    packet.question.each do |q|
      $logger.debug "#{client_info} requested an #{q.qtype} record for #{q.qname}"
      @backend.handle(q,packet)
    end
    
    begin
      send_datagram(packet.encode, host, port)
    rescue Exception => e
      $logger.error "Error decoding packet: #{e.inspect}"
      #$logger.error e.backtrace.join("\r\n")
    end

  end # receive_data

  def shutdown
    raise RuntimeError, "pid_file not defined in configuration" unless CONFIG[:pid_file]
    File.delete(CONFIG[:pid_file])
  end #shutdown

end # EventDns
