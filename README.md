# mdl

python module for interacting with data from malwaredomainlist.com

# Usage

  import mdl

  # fetch a copy of the malware domain list csv
  d = mdl.Downloader()
  d.fetch()

  m = mdl.MalwareDomainList()

  # run a query by IP address
  results = m.search_ip('190.120.228.92')


# Installation 

  python setup.py install



