#/usr/local/bin/ruby19

# https://github.com/nullstream/spf_dump

require "pp"
require 'ipaddr'
# IPAddr.new('192.168.0.1/24').to_range.each { |i| puts i};

class	SPF
	def initialize( debug = false )
		@debug = debug
	end
	def log( str )
		puts str if @debug
	end
	def dig( domain, type )
		log "*** dig #{domain} #{type} +short"
		`dig #{domain} #{type} +short`.gsub( /\"/, '' )
	end
	def handle_a( ip )
		log "* handle a for #{ip}"
		dig( ip, 'a' ).split.map do | token |
			token
		end
	end
	def handle_mx( ip )
		log "* handle mx for #{ip}"
		dig( ip, 'mx' ).split(/\n/).map do | token |
			handle_a( ( token.split() )[ 1 ] )
		end.flatten
	end
	def parse( domain )
		ranges = []
		record = dig( domain, 'txt' ).downcase
		record.split.each do | token |
			log "* found token #{token}"
			token = token.split(/:|=/)
			if token.length == 2
				case token.first
				when 'ip4'
					log "* scan ip4 #{token[1]}"
					ranges.push( token[1] )
				when 'a'
				 	log "* scan a #{token[1]}"
					ranges.concat( handle_a( token[ 1 ] ) )
				when 'mx'
					log "* scan mx #{token[1]}"
					ranges.concat( handle_mx( token[ 1 ] ) )
				when 'include', 'redirect'
					log "* scan include or redirect #{token[1]}"
					ranges.concat( parse( token[ 1 ] ) )
				else
					log "* scan unknown #{token}"
				end
			else
				log "* ELSE #{token.first}"
				case token.first
				when 'a', '?all', 'ptr'
					log "* scan ?all for #{domain}"
					ranges.concat( handle_a( domain ) )
				when 'mx', '+mx'
					log "* scan +mx for #{domain}"
					ranges.concat( handle_mx( domain ) )
				else
					alt = token.first.split( /=/ )
					case alt.first
					when 'redirect'
						log "* redirect for #{alt.last}"
						ranges.concat( parse( alt.last ) )
					else
						log "** alt: " + token.first
					end
				end
			end
		end
		log "----------#{domain}-------------"
		# pp ranges
		ranges
	end
end

spf = SPF.new( false )
puts spf.parse( ARGV.first ).uniq
#spf.parse( ARGV.first ).uniq.each do | ip |
#	IPAddr.new( ip ).to_range.each { |i| puts i };
#end
