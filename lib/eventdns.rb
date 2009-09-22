class EventDns < EventMachine::Connection
  @backend = nil
  attr_accessor :host, :port
  def initialize
    @backend = UseBackend.new(CONFIG[:driver])
    $logger.debug "Handling query via the #{CONFIG[:driver]} Backend."

    return unless CONFIG[:driver] == 'http'

    # Push a test query through our driver to make sure we have connectivity.
    #FIXME: This needs to get cleaned up, made smaller, or something.
    test = Dnsruby::Message.new
    test.add_question('pi.http.viadns.org', Dnsruby::Types.A, Dnsruby::Classes.IN)

    test.question.each do |q|
      $logger.debug "Startup test: Requesting an #{q.qtype} record for #{q.qname}"
      @backend.handle(q,test)
    end

    error = false
    error = true unless test.answer[0].name.to_s == 'pi.http.viadns.org'
    error = true unless test.answer[0].address.to_s == '3.14.159.26'
    if error
      raise LoadError, "Unable to run test query!"
    else
      $logger.debug "Test successful!"
    end
      
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
end # EventDns
