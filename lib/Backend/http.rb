require 'ipaddr'
require 'rubygems'
require 'open-uri'
require 'json'
require 'pp'
require 'logger'

LOGGER = Logger.new(STDOUT)
LOGGER.level = Logger::DEBUG
#LOGGER.level = Logger::WARN
#LOGGER.level = Logger::FATAL

class String
  def octets
    count = 0
    self.each_byte { count += 1 }
    return count
  end
end # String
    
def is_domain_name(domain)
  # Regular expression from: http://www.shauninman.com/archive/2006/05/08/validating_domain_names (Thanks!)
  match = domain.match(/^([a-z0-9]([-a-z0-9]*[a-z0-9])?\.)+((a[cdefgilmnoqrstuwxz]|aero|arpa)|(b[abdefghijmnorstvwyz]|biz)|(c[acdfghiklmnorsuvxyz]|cat|com|coop)|d[ejkmoz]|(e[ceghrstu]|edu)|f[ijkmor]|(g[abdefghilmnpqrstuwy]|gov)|h[kmnrtu]|(i[delmnoqrst]|info|int)|(j[emop]|jobs)|k[eghimnprwyz]|l[abcikrstuvy]|(m[acdghklmnopqrstuvwxyz]|mil|mobi|museum)|(n[acefgilopruz]|name|net)|(om|org)|(p[aefghklmnrstwy]|pro)|qa|r[eouw]|s[abcdeghijklmnortvyz]|(t[cdfghjklmnoprtvwz]|travel)|u[agkmsyz]|v[aceginu]|w[fs]|y[etu]|z[amw])\.?$/i)
  if match == nil
    LOGGER.warn "Domain '#{domain}' is invalid."
    return false
  end
  
  return true
end # is_domain_name
    
module Backend
  module HTTP
    class Lookup
      def query(query,base_url='http://example.com/')
        url = base_url + "#{query[:name]}?type=#{query[:type]}"
        LOGGER.debug "Looking up URL: #{url}"
        return Zone.new(url)
      end
    end # Lookup

    class Zone
      attr_reader :results
      def initialize(url)
        begin
          rv = open(url)
          @results = JSON.parse(rv.read)
          @results.map!{|result| RR.new(result)}
        rescue OpenURI::HTTPError => e
          LOGGER.debug "Skipping error: #{e.message}"
          @results = []
        end
      end # initialize
      def valid?
        rv = self.results.map{|result| result.valid?}.uniq
        if rv.length == 1 and rv[0] == true
          return true
        else
          return false
        end
      end # valid?
    end # Zone
    
    class RR
      attr_accessor :name, :ttl, :type, :rdata
      def initialize(result)
        @name  = result['name']
        @ttl   = result['ttl']
        @type  = result['type']
        @rdata = result['rdata']
      end
      def valid?
        # Validate the "name" attribute
        # RFC 1035 2.3.4. "Size Limits"
        min_name_octets = 0
        max_name_octets = 255
        return false unless self.name.octets >= min_name_octets
        return false unless self.name.octets <= max_name_octets
        
        # Validate the "ttl" attribute
        # RFC 1035 2.3.4. "Size Limits"
        max_ttl_value = 2**31 - 1 # "positive values of a signed 32 bit number."
        
        begin
          Integer(self.ttl)
        rescue ArgumentError
          LOGGER.warn "Invalid TTL: '#{self.ttl}'"
          return false
        end
        ttl = Integer(self.ttl)
        return false unless ttl >= 0 and ttl <= max_ttl_value
        
        # Validate the "type" attribute
        # Taken from: http://en.wikipedia.org/wiki/List_of_DNS_record_types
        valid_types = ['A','AAAA','AFSDB','CERT','CNAME','DHCID','DLV','DNAME','DNSKEY','DS','HIP','IPSECKEY','KEY','LOC','MX','NAPTR','NS','NSEC','NSEC3','NSEC3PARAM','PTR','RRSIG','SIG','SOA','SPF','SRV','SSHFP','TA','TXT']
        return false unless valid_types.include?(self.type)
        
        # Validate the "rdata" attribute
        # RFC 1035 3.2.1. "RR definitions", "Format"
        begin
          rdata = RDATA.new(self.rdata)
        rescue Exception => e
          LOGGER.warn "Error converting '#{self.rdata}' to RDATA: #{e}"
          return false
        end
        max_rdata_octets = 2**16 - 1 # RDLENGTH is an unsigned 16 bit integer.
        return false unless rdata.octets <= max_rdata_octets
        
        type_is_valid = true
        case self.type
        when 'CNAME', 'NS', 'PTR'
          type_is_valid = false unless rdata.is_domain_name?
        when 'MX'
          type_is_valid = false unless rdata.is_mx?
        when 'A'
          type_is_valid = false unless rdata.is_ipaddr?
        when 'NULL','TXT'
        when 'HINFO','MB','MD','MF','MG','MINFO','MR','SOA','WKS'
          type_is_valid = :unknown
        else
          type_is_valid = false
        end
        return false unless type_is_valid == true
        
        # Return true if all tests pass.
        return true
      end
      def to_s
        "%s. %d %s %s" % [self.name, self.ttl, self.type, self.rdata]
      end
    end
    
    class RDATA < String
      # RFC 1035 3.3.1. "CNAME RDATA format"
      # RFC 1035 3.3.11. "NS RDATA format"
      # RFC 1035 3.3.12. "PTR RDATA format"
      def is_domain_name?
        return is_domain_name(self)
      end # is_domain_name?
      
      # RFC 1035 3.3.9. "MX RDATA format"
      ## PREFERENCE (16 bit integer (unsigned?), lower is preferred)
      ## EXCHANGE   domain-name
      def is_mx?
        # The min and max values below assume that the PREFERENCE field is an unsigned 16 bit integer.
        min_preference_value = 0
        max_preference_value = 2**16 - 1
        
        mx = self.match(/^([0-9]+)\ (.*?)$/)
        if mx == nil or mx[1] == nil or mx[2] == nil
          LOGGER.warn "MX '#{self}' requires valid preference and exchange fields."
          return false
        end
        preference = mx[1].to_i
        exchange = mx[2].to_s
        if preference > max_preference_value
          LOGGER.warn "MX '#{self}' PREFERENCE value must not exceed #{max_preference_value}."
          return false
        end
        if preference < min_preference_value
          LOGGER.warn "MX '#{self}' PREFERENCE value must be greater than #{min_preference_value}."
          return false
        end
        return false unless is_domain_name(exchange)

        return true
      end # is_mx?
      
      # RFC 1035 3.4.1. "A RDATA format"
      def is_ipaddr?
        begin
          ip = IPAddr.new(self)
          return ip.to_s == self
        rescue ArgumentError
          return false
        end
      end # is_ipaddr?

    end # RDATA

  end # HTTP
end # Backend
