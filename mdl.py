#!/usr/bin/python
"""
Python client for Malware Domain List <http://www.malwaredomainlist.com/>
Copyright (C) 2012 Brandon Archer 

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
import sys
import os
import csv
import time
import urllib2

# Malware domain list CSV column mappings
MDL_DATE        = 0
MDL_DOMAIN      = 1
MDL_IP          = 2
MDL_REVERSE     = 3 
MDL_DESCRIPTION = 4
MDL_REGISTRANT  = 5
MDL_ASN         = 6
MDL_INACTIVE    = 7
MDL_COUNTRY     = 8

# Forward or reverse domain lookup flags
DOMAIN_BOTH     = 0
DOMAIN_FORWARD  = 1
DOMAIN_REVERSE  = 2

# Defaults
MDL_PATH = os.path.expanduser('~')
MDL_FILE = 'mdl.csv'
MDL_MAX_AGE = 7 # days
MDL_SHOW_INACTIVE = False

class OutdatedMDLException(Exception):
  pass


class Downloader(object):

  download_url = 'http://www.malwaredomainlist.com/mdlcsv.php'

  def fetch(self, destination="%s/%s" % (os.path.expanduser(MDL_PATH),MDL_FILE)):
    """
    Fetches a copy of the Malware domain list full CSV database from %s

    @param destination: Destination file name to save the file to (default: '~/mdl.csv')
    @type destination: str
    """ % self.download_url

    response = urllib2.urlopen(self.download_url)
    handle = open(destination, 'w')
    
    for line in response:
      handle.write(line)
    
    handle.close()


class MalwareDomainList(object):

  def __init__(self, filename=os.path.join(MDL_PATH, MDL_FILE), 
                     show_inactive=False, 
                     max_age=MDL_MAX_AGE):
    """
    Initialize the class

    @param filename: path to the malware domain list CSV file. Default ~/mdl.csv
    @type filename: str

    @param show_inactive: Return results marked inactive in the malware domain list. Default false.
    @type show_inactive: bool

    @param max_age: Max age of MDL file in days. If MDL is older than max_age an OutdatedMDLException is raised. Default value is %d days.
    @type: int
    """ % MDL_MAX_AGE
    self.mdl_file = filename
    self.mdl_show_inactive = show_inactive
    self.mdl_file_age = self.get_mdl_age()
    self.mdl_max_age = max_age

    if self.mdl_file_age >= int(max_age):
     raise OutdatedMDLException("The malware domain list file %s is older than the threshold of %d days." % (filename, max_age))
      
    filehandle = csv.reader(open(filename, 'rb'))

    self._mdl = []
  
    for line in filehandle:
      self._mdl.append(line)

  def get_mdl_age(self):
    """
    Calculate number of days since file last updated

    @return: Number of days since update
    @rtype: int
    """
    mtime = os.path.getmtime(self.mdl_file)
    ctime = time.time()
    return (ctime - mtime) / 86400 #  seconds in a day

  def _inactive(self, record):
    """
    Check if record is marked inactive.

    @param record: a row of fields from the malware domain list.
    @type: tuple

    @return: True if field is marked inactive, False otherwise.
    @rtype: bool
    """
    if int(record[MDL_INACTIVE]) == 1:
      return True
    else:
      return False

  def _pack_results(self, record):
    """
    Pack ordered list from mdl into dict object.

    @param record: A single row from the mdl csv.
    @type: list

    @return: dict with date, domain, ip, reverse, description, registrant
             asn, inactive, country or empty dict if not found
    @rtype: dict
    """
    return {
        'date' : record[MDL_DATE],
        'domain' : record[MDL_DOMAIN],
        'ip' : record[MDL_IP],
        'reverse' : record[MDL_REVERSE],
        'description' : record[MDL_DESCRIPTION],
        'registrant' : record[MDL_REGISTRANT],
        'asn' : record[MDL_ASN],
        'inactive' : record[MDL_INACTIVE],
        'country' : record[MDL_COUNTRY]
      }

  def show_inactive(self, show_inactive=MDL_SHOW_INACTIVE):
    """
    Show records marked inactive in MDL. Default %s

    @param show_inactive: If True inactive records from the malware domain list may be return in results. 
    @type show_inactive: bool
    """ % MDL_SHOW_INACTIVE
    self.mdl_show_inactive = show_inactive

  def search_ip(self, addr):
    """
    Search malware domain list for IP address

    @param addr: IP address 
    @type addr: str

    @return: dict with date, domain, ip, reverse, description, registrant
             asn, inactive, country or empty dict if not found
    @rtype: dict
    """
    for record in self._mdl:
      if len(record) > 0:
        
        if self._inactive(record) and not self.mdl_show_inactive:
          continue

        ip = record[MDL_IP] 
        
        if "/" in record[MDL_IP]:
          ip = record[MDL_IP].split("/")[0]
        
        elif ":" in record[MDL_IP]:
          ip = record[MDL_IP].split(":")[0]
        
        if addr.strip() == ip.strip():
          return self._pack_results(record)   
    return {} # No match

  def search_domain_forward(self, domain):
    """
    Search malware domain list for domain that matches forward DNS address.

    @param domain: Domain
    @type domain: str

    @return: list of dict objects with date, domain, ip, reverse, description, 
             registrant, asn, inactive, country or empty dict if not found
    @rtype: list  
    """
    results = []
    for record in self._mdl:
      if len(record) > 0:

        if self._inactive(record) and not self.mdl_show_inactive:
          continue

        if record[MDL_DOMAIN].find(domain) >= 0:
          results.append(self._pack_results(record))
    return results 

  def search_domain_reverse(self, domain):
    """
    Search malware domain list for domain that matches reverse DNS address.

    @param domain: Domain
    @type domain: str

    @return: list of dict objects with date, domain, ip, reverse, description, 
             registrant, asn, inactive, country or empty dict if not found
    @rtype: list  
    """
    results = []
    for record in self._mdl:
      if len(record) > 0:

        if self._inactive(record) and not self.mdl_show_inactive:
          continue

        if record[MDL_REVERSE].find(domain) >= 0:
          results.append(self._pack_results(record))
          
    return results 

  def search_domain(self, domain, flags=DOMAIN_BOTH):
    """
    Search malware domain list for domain

    @param domain: Domain
    @type domain: str

    @param flags: Search domains using forward lookup, reverse lookup or both.

           Values:
           DOMAIN_BOTH = 0 (Default)
           DOMAIN_FORWARD = 1
           DOMAIN_REVERSE = 2
    
    @type int

    @return: list of dict objects with date, domain, ip, reverse, description, 
             registrant, asn, inactive, country or empty dict if not found
    @rtype: list 
    """
    if flags == DOMAIN_BOTH:
      r1 = self.search_domain_forward(domain)
      r2 = self.search_domain_reverse(domain)
      return r1 + r2 
    elif flags == DOMAIN_FORWARD:
      return self.search_domain_forward(domain)
    elif flags == DOMAIN_REVERSE:
      return self.search_domain_reverse(domain)
    else:
      raise Exception, "Unknown flag %s" % flags


