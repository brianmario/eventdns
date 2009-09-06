class UseBackend
  @backend = nil
  @cache = nil

  def initialize(backend='default')
    #FIXME: Throw an error if the backend doesn't exist.
    #TODO: Eventually we should just look for a Backend::#{backend}::Lookup class
    @backend = backend.to_sym
    @cache = SimpleCache.new()
  end

  def handle(q,packet)
    self.send @backend, q, packet
  end # handle

  def default(q,packet)
    $logger.debug "#{q.qname} is 127.0.0.1, handing back to client"
    record = Dnsruby::RR.create(:name => q.qname, :type => "A", :ttl => 360, :address => "127.0.0.1")
    packet.header.qr = 1 # This is a Query Response
    packet.header.aa = 1 # This is an Authoritative Answer
    packet.add_answer(record)
  end # default

  def http(q,packet)
    key = "#{q.qname}-#{q.qtype}-#{CONFIG[:base_url]}"
    query = @cache.get(key)
    if query == nil # cache miss
      $logger.debug "Cache miss :("
      begin
        lookup = Backend::HTTP::Lookup.new()
        value = lookup.query({:name => q.qname,:type => q.qtype},CONFIG[:base_url])
      rescue Exception => e
        $logger.error "Error running query: #{e.inspect}"
        value = nil
      end
      @cache.set(key,value)
      query = value
    end

    # We are always sending a Query Response
    packet.header.qr = true

    if q.qtype == 'SOA'
      # Recursion Available
      #FIXME: I'm only setting this for now since this flag always seems to be set on SOA replies ...
      packet.header.ra = true 
    else
      # This is an Authoritative Answer
      packet.header.aa = true 
    end 

    unless query.valid?
      $logger.debug "Sending NXDomain"
      packet.header.rcode='NXDomain'
      return
    end
  
    query.results.each do |result|
      return unless result.is_a? Backend::HTTP::RR
      $logger.debug "Adding answer: '#{result.to_s}'"
      packet.add_answer(Dnsruby::RR.create(result.to_s))
    end
  end # http

end # UseBackend
