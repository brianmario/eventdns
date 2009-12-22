# json-dig.rb
#
# Like dig(1) but return packet in JSON format!
#
# usage: ruby json-dig.rb example.com A
require 'rubygems'
require 'dnsruby'
require 'json'
require 'pp'

class Dnsruby::Header
  def make_json(*args)
    rv = Hash.new()
    self.instance_variables.each do |key|
      value = self.instance_variable_get(key)
      next if value == false
      rv[key.sub('@','')] = value
    end
    rv
  end # make_json
end

class Dnsruby::Question
  def make_json(*args)
    rv = Hash.new()
    ['qname','qtype','qclass'].each do |key|
      rv[key] = self.instance_variable_get('@' + key).to_s
    end
#    '{"QCLASS":"%s","QTYPE":"%s","QNAME":"%s"}' % [rv['qclass'],rv['qtype'],rv['qname']]
    rv
  end # make_json
end

class Dnsruby::RR
  def make_json(*args)
    rv = Hash.new()
    ['name','type','klass','ttl','rdata'].each do |key|
      name = key
      if key == 'klass'
        name = 'class'
      end
      rv[name] = self.instance_variable_get('@' + key)
    end
    rv
  end # make_json
end

class Array
  def make_json(*args)
    self.map { |element| element.make_json(*args) }
  end
end

class Dnsruby::Message
  def make_json(*args)
    rv = Hash.new()
    ['header','question','answer','authority','additional'].each do |part|
#    ['question'].each do |part|
      rv[part] = self.instance_variable_get('@' + part).make_json
     end
    rv
  end # make_json
end # Dnsruby::Message

include Dnsruby
res = Dnsruby::Resolver.new
qdomain = 'example.com'
qtype = 'A'
qdomain = ARGV[0] if ARGV[0]
qtype = ARGV[1] if ARGV[1]

begin
  response = res.send_message(Message.new(qdomain, Types.send(qtype)))
rescue ResolvError
  # ...
rescue ResolvTimeout
  # ...
end

puts JSON.pretty_generate(response.make_json)
