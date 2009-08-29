# encoding: UTF-8
require File.expand_path(File.dirname(__FILE__) + '/../spec_helper.rb')

describe Backend::HTTP::Zone do
  before(:all) do
    @fixture = File.dirname(__FILE__) + '/fixtures/'
  end

  it "correctly parses example Gmail results" do
    @dns = Backend::HTTP::Zone.new(@fixture + 'gmail')
    @dns.results[1].name.should  == 'example.com'
    @dns.results[1].ttl.should   == 3600
    @dns.results[1].type.should  == 'MX'
    @dns.results[1].rdata.should == '5 ALT1.ASPMX.L.GOOGLE.com.'
  end

  it "correctly handles bad input: invalid type" do
    @dns = Backend::HTTP::Zone.new(@fixture + 'invalid-type')
    @dns.valid?.should  == false
  end

  it "correctly handles bad input: invalid name" do
    @dns = Backend::HTTP::Zone.new(@fixture + 'invalid-name')
    @dns.valid?.should  == false
  end

  it "correctly validates good input: example Gmail results" do
    @dns = Backend::HTTP::Zone.new(@fixture + 'gmail')
    @dns.valid?.should == true
  end

  it "correctly validates good input: valid types" do
    @dns = Backend::HTTP::Zone.new(@fixture + 'valid-type')
    @dns.valid?.should  == true
  end

  it "can handle valid? being called more than once" do
    @dns = Backend::HTTP::Zone.new(@fixture + 'valid-type')
    @dns.valid?.should  == true
    @dns.valid?.should  == true
    @dns.valid?.should  == true
  end

  it "correctly handles 404s" do
    @dns = Backend::HTTP::Zone.new('http://example.com/404')
    @dns.valid?.should == false
  end

  it "correctly constructs a query with the type in the URL" do
    @dns = Backend::HTTP::Zone.new('http://example.com/404')
    @dns.valid?.should == false
  end

end # Backend::HTTP::Zone

describe Backend::HTTP::RR do
  before(:all) do
    @rr = {'name'=>'example.com','ttl'=>'0','type'=>'A','rdata'=>'0.0.0.0'}
  end

  it "correctly validates NAME values" do
    Backend::HTTP::RR.new(@rr.merge({'name'=>''})).valid?.should == true
    Backend::HTTP::RR.new(@rr.merge({'name'=>'X'*255})).valid?.should == true
    Backend::HTTP::RR.new(@rr.merge({'name'=>'X'*256})).valid?.should == false
  end

  it "correctly validates TTL values" do
    Backend::HTTP::RR.new(@rr.merge({'ttl'=>'NOPE'})).valid?.should == false
    Backend::HTTP::RR.new(@rr.merge({'ttl'=>'12C'})).valid?.should == false
    Backend::HTTP::RR.new(@rr.merge({'ttl'=>'-1'})).valid?.should == false
    Backend::HTTP::RR.new(@rr.merge({'ttl'=>'0'})).valid?.should == true
    Backend::HTTP::RR.new(@rr.merge({'ttl'=>'1'})).valid?.should == true
    Backend::HTTP::RR.new(@rr.merge({'ttl'=>'1337'})).valid?.should == true
    Backend::HTTP::RR.new(@rr.merge({'ttl'=>'2147483647'})).valid?.should == true
    Backend::HTTP::RR.new(@rr.merge({'ttl'=>'2147483648'})).valid?.should == false
    Backend::HTTP::RR.new(@rr.merge({'ttl'=>'99999999999'})).valid?.should == false
  end

  it "correctly validates TYPE values" do
    [nil,true,false,'',1234,'FAKE','AA','AAA','ANAME'].each do |type|
      Backend::HTTP::RR.new(@rr.merge({'type'=>type})).valid?.should == false
    end
  end

  it "correctly validates RDATA values" do
    [nil,true,false,1,2,3,4].each do |type|
      Backend::HTTP::RR.new(@rr.merge({'type'=>'TXT','rdata'=>type})).valid?.should == false
    end
  end

  it "doesn't allow RDATA values larger than 2^16" do
    Backend::HTTP::RR.new(@rr.merge({'type'=>'TXT','rdata'=>'x'*(2**16 - 1)})).valid?.should == true
    Backend::HTTP::RR.new(@rr.merge({'type'=>'TXT','rdata'=>'x'*(2**16)})).valid?.should == false
    Backend::HTTP::RR.new(@rr.merge({'type'=>'TXT','rdata'=>'x'*(2**17)})).valid?.should == false
  end

  it "correctly validates CNAME, NS, PTR records" do
    ['CNAME','NS','PTR'].each do |type|
      ['example.com','example.com.','mx.example.com','a.b.c.e.f.g.h.i.j.example.com',
      ].each do |domain|
        Backend::HTTP::RR.new(@rr.merge({'type'=>type,'rdata'=>domain})).valid?.should == true
      end
      
      ['10.0.0.1','1000','com','net','org'
      ].each do |domain|
        Backend::HTTP::RR.new(@rr.merge({'type'=>type,'rdata'=>domain})).valid?.should == false
      end
    end
  end

  it "correctly validates MX records" do
    Backend::HTTP::RR.new(@rr.merge({'type'=>'MX','rdata'=>'10 mx.example.com.'})).valid?.should == true
    Backend::HTTP::RR.new(@rr.merge({'type'=>'MX','rdata'=>'10mx.example.com.'})).valid?.should == false
  end

  it "correctly validates A records" do
    ['0.0.0.0','1.2.3.4','192.168.0.0','10.0.0.0',
     '10.10.10.255','10.10.255.10','10.255.10.10','255.10.10.10',
     '10.10.255.255','10.255.255.10','255.255.10.10',
     '10.255.255.255','255.255.255.10','255.255.255.255',
    ].each do |ip|
      Backend::HTTP::RR.new(@rr.merge({'type'=>'A','rdata'=>ip})).valid?.should == true
    end

    ['10.10.10.256','10.10.256.10','10.256.10.10','256.10.10.10',
     '10.10.256.256','10.256.256.10','256.256.10.10',
     '10.256.256.256','256.256.256.10','256.256.256.256',
     '999.999.999.999','9999999.9999999.9999999.9999999',
    ].each do |ip|
      Backend::HTTP::RR.new(@rr.merge({'type'=>'A','rdata'=>ip})).valid?.should == false
    end
  end

  it "correctly converts to a string" do
    Backend::HTTP::RR.new(@rr).to_s.should == 'example.com. 0 A 0.0.0.0'
    Backend::HTTP::RR.new(@rr.merge({'ttl'=>'10','type'=>'MX','rdata'=>'10 mx.example.com'})).to_s.should == 'example.com. 10 MX 10 mx.example.com'
    
  end

end # Backend::HTTP::RR

describe Backend::HTTP::RDATA do
  it "can deal with a string" do
    string = 'I am a string'
    rdata = Backend::HTTP::RDATA.new(string)
    rdata.should == string
  end

  it "correctly validates domain names" do
    ['google.com','google.com.'].each do |domain|
      rdata = Backend::HTTP::RDATA.new(domain)
      rdata.is_domain_name?.should == true
    end
  end

  it "recognizes valid MX values" do
    ['1 ASPMX.L.GOOGLE.com.',
     '5 ALT1.ASPMX.L.GOOGLE.com.',
     '5 ALT2.ASPMX.L.GOOGLE.com.',
     '10 ASPMX2.GOOGLEMAIL.com.',
     '10 ASPMX3.GOOGLEMAIL.com.',
     '10 ASPMX4.GOOGLEMAIL.com.',
     '10 ASPMX5.GOOGLEMAIL.com.',
     '1 example.com',
     '10 example.com',
     '100 example.com',
     '1000 example.com',
     '1 example.com.',
     '10 example.com.',
     '100 example.com.',
     '1000 example.com.',
     "#{2**16 - 1} example.com",
     "#{2**16 - 1} example.com."].each do |mx|
      rdata = Backend::HTTP::RDATA.new(mx)
      rdata.is_mx?.should == true
    end
  end

  it "recognizes invalid MX values" do
    ['1ASPMX.L.GOOGLE.com.',
     '10ASPMX5.GOOGLEMAIL.com.',
     "#{2**16} example.com",
     "#{2**16} example.com.",
     '1 10.0.0.1',
     '2 192.168.0.1',
    ].each do |mx|
      rdata = Backend::HTTP::RDATA.new(mx)
      rdata.is_mx?.should == false
    end
  end

end # Backend::HTTP::RDATA
