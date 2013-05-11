spf_dump
========

instead of manually find all ips for domains MX records use spf_dump to find and dump them out

because I don't enjoy python I rewrote the https://github.com/nullstream/spf_dump to ruby

     # chmod +x spf_dump
     # ./spf_dump [domainname]

... lists all ip's from the given spf record for this domain.
you can now pipe them into pfctl with

     # ./spf_dump | pfctl -t whitelist -T add

please let me know if there are errors.
