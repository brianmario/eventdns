# encoding: UTF-8
require File.expand_path(File.dirname(__FILE__) + '/../spec_helper.rb')
require 'rubygems'
require 'logging'
require 'dnsruby'

module EventMachine
  class Connection
    @mock_datagram = {}
    def get_peername
      return ('  ' + [1234,10,12,34,56].pack("nC4"))
    end
    def send_datagram(packet,host,port)
      @mock_datagram = {
        :packet => packet,
        :host => host,
        :port => port,
      }
    end
    def send_datagram_results
      return @mock_datagram
    end
  end
end

require File.expand_path(File.dirname(__FILE__) + '/../../lib/usebackend.rb')

CONFIG = {
  :bind_address => '0.0.0.0',
  :bind_port => 1053,
  :backend => 'default',
  :base_url => 'http://www.domdori.com/dns/records/',
  :pid_file => 'log/test.pid',
  :startup_test => ['pi.http.viadns.org','3.14.159.26'],
}

$logger = Logging.logger(STDOUT)
#$logger.level = :debug
$logger.level = :fatal


require File.expand_path(File.dirname(__FILE__) + '/../../lib/eventdns.rb')

describe EventDns do
  before(:each) do
    @dns = EventDns.new()
  end

  it "has a working get_peername replacement" do
    # client_info uses get_peername
    @dns.new_connection
    @dns.client_info.should == '10.12.34.56:1234'
  end

  it "has a working send_datagram replacement" do
    @dns.send_datagram('notreallyadatagram','10.12.34.56',1234)
    @dns.send_datagram_results.should == {:packet => 'notreallyadatagram', :host => '10.12.34.56', :port => 1234}
  end

  it "correctly handles input data with a size of 0" do
    @dns.receive_data('').should == nil
  end

  it "can handle invalid input data" do
    ['',1,'1',:packet,'1234567'].each do |input|
      dns = EventDns.new()
      dns.receive_data('1').should == nil
    end
  end

  it "works with one simple question using the default backend" do
    message = Dnsruby::Message.new
    message.header.rd = 1
    message.add_question('testing.example.com', Dnsruby::Types.A, Dnsruby::Classes.IN)

    @dns.receive_data(message.encode).should_not == nil
    results = @dns.send_datagram_results
    answer = Dnsruby::Message.decode(results[:packet]).answer[0]
    answer.address.to_s.should == '127.0.0.1'
    answer.name.to_s.should == 'testing.example.com'
  end

  it "can handle with input data with multiple questions using the default backend" do
    message = Dnsruby::Message.new
    message.header.rd = 1
    message.add_question('one.example.com', Dnsruby::Types.A, Dnsruby::Classes.IN)
    message.add_question('two.example.com', Dnsruby::Types.A, Dnsruby::Classes.IN)

    @dns.receive_data(message.encode).should_not == nil
    results = @dns.send_datagram_results
    reply = Dnsruby::Message.decode(results[:packet])
    reply.answer[0].address.to_s.should == '127.0.0.1'
    reply.answer[0].name.to_s.should == 'one.example.com'
    reply.answer[1].address.to_s.should == '127.0.0.1'
    reply.answer[1].name.to_s.should == 'two.example.com'
  end

  it "can resolve pi.http.viadns.org using the HTTP backend" do
    message = Dnsruby::Message.new
    message.add_question('pi.http.viadns.org', Dnsruby::Types.A, Dnsruby::Classes.IN)
    CONFIG[:backend] = 'http'
    dns = EventDns.new()
    dns.receive_data(message.encode).should_not == nil
    results = dns.send_datagram_results
    reply = Dnsruby::Message.decode(results[:packet])
    reply.answer[0].name.to_s.should == 'pi.http.viadns.org'
    reply.answer[0].address.to_s.should == '3.14.159.26'
  end

  it "can handle with input data with multiple questions using the HTTP backend" do
    message = Dnsruby::Message.new
    message.header.rd = 1
    message.add_question('memes.http.viadns.org', Dnsruby::Types.TXT, Dnsruby::Classes.IN)
    message.add_question('numbers.http.viadns.org', Dnsruby::Types.TXT, Dnsruby::Classes.IN)

    @dns.receive_data(message.encode).should_not == nil
    results = @dns.send_datagram_results
    reply = Dnsruby::Message.decode(results[:packet])
    answers = {}
    reply.answer.each do |answer|
      answers[answer.name.to_s] = [] unless answers[answer.name.to_s].is_a? Array
      answers[answer.name.to_s].push(answer.rdata.to_s)
    end
    answers.each do |key,value|
      answers[key] = value.sort!
    end
    answers['numbers.http.viadns.org'].should == ['0','1','2','3','4','5','6','7','8','9']
    answers['memes.http.viadns.org'].should == ['All your base are belong to us',
                                                'Badger Badger Badger', 
                                                'Jia Junpeng, your mother is calling you home for dinner']
  end

  it "writes it's PID to a file" do 
    pid = File.read(CONFIG[:pid_file]).chomp.to_i
    pid.should == Process.pid
  end

  it "cleans up it's PID file when the shutdown method is called" do
    dns = EventDns.new()
    pid = File.read(CONFIG[:pid_file]).chomp.to_i
    pid.should == Process.pid
    dns.shutdown
    File.exist?(CONFIG[:pid_file]).should == false
  end

## I'm not sure what sorts of tests to use here ... 
#   it "can handle malicious input data" do
#   end

#   it "" do
#   end

end
