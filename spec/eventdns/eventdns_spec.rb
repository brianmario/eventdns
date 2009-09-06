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
  :driver => 'default',
  :base_url => 'http://www.domdori.com/dns/records/',
}

$logger = Logging.logger(STDOUT)
$logger.level = :debug


require File.expand_path(File.dirname(__FILE__) + '/../../lib/eventdns.rb')

describe EventDns do
  it "has a working get_peername replacement" do
    dns = EventDns.new()

    dns.new_connection
    # client_info uses get_peername
    dns.client_info.should == '10.12.34.56:1234'
  end

  it "has a working send_datagram replacement" do
    dns = EventDns.new()

    dns.send_datagram('notreallyadatagram','10.12.34.56',1234)
    dns.send_datagram_results.should == {:packet => 'notreallyadatagram', :host => '10.12.34.56', :port => 1234}
  end

  it "works with one simple question" do
    message = Dnsruby::Message.new
    message.header.rd = 1
    message.add_question('testing.example.com', Dnsruby::Types.A, Dnsruby::Classes.IN)

    dns = EventDns.new()
    dns.new_connection
    dns.receive_data(message.encode)
    results = dns.send_datagram_results
    answer = Dnsruby::Message.decode(results[:packet]).answer[0]
    answer.address.to_s.should == '127.0.0.1'
    answer.name.to_s.should == 'testing.example.com'
  end

#   it "correctly handles input data with a size of 0" do
#   end

#   it "can handle malformed input data" do
#   end

#   it "works with input data with just one question" do
#   end

#   it "works with input data with more than one question" do
#   end

#   it "" do
#   end

end
