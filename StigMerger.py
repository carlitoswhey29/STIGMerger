# ===================================================================
# .Author: Carlos Aguilar
# .Description:  
#    Copies the information from the old STIG onto a the new STIG. 
# .Paramaters:
#     "Usage: {stigMerger.py} <old_STIG> <new_STIG> <xsl_format>"
#
# .TODO: 
#     -Reduce complextity of writing.
#     -Eliminate the use of multiple xml libraries
#
# ===================================================================

import sys
import lxml.etree as xsET
from xml.dom.minidom import parseString
import xml.etree.ElementTree as ET

class Checklist:
    def __init__(self, id, comment, status):
        self.id = id
        self.status = status
        self.comment = comment

def write_to_XML(outfilename, data, legacy):
    # Open original file
    tree = ET.parse(outfilename)
    ckl_root = tree.getroot() # element
    ckl = ckl_root.getchildren()  # list
    istigs = ckl[1]
    vulns_elist = istigs[0]
    v_start = 1 
    v_end = len(vulns_elist) - 1
    for d in data:
      # complexity too high since if it's sorted
      for i in range(v_start, v_end): 
        vuln = vulns_elist[i] 
        if(legacy != True):
          v_id = vuln[0].find('ATTRIBUTE_DATA')
        else:
          v_id = vuln[25].find('ATTRIBUTE_DATA')
        if(d.id == v_id.text):
          status = vuln.find('STATUS')
          status.text = d.status
          comment = vuln.find('COMMENTS')
          comment.text = d.comment
          break
      
    tree.write(outfilename, encoding="UTF-8", xml_declaration=True, short_empty_elements=False)

def get_vulnerability_data(tagName, lst):
    for vuln in tagName:
        status = vuln.getElementsByTagName('STATUS')[0].firstChild.data
        vuln_num = vuln.getElementsByTagName('ATTRIBUTE_DATA')[0].firstChild.data
        comment = vuln.getElementsByTagName('COMMENTS')[0].firstChild
        if(comment != None):
          text = vuln.getElementsByTagName('COMMENTS')[0].firstChild.data  # Type: 1
        else:
          text = ' '
        stig = Checklist(vuln_num, text, status)
        lst.append(stig)
    print ("Parsing Complete...")
    return lst

def parse_xml(filename):
    # Open original file
    file = open(filename) #parse an XML file by name
    data = file.read()
    dom = parseString(data)
    return dom

def formatCKL(xml_filename, xsl_filename):
  dom = xsET.parse(xml_filename)
  xslt = xsET.parse(xsl_filename)
  transform = xsET.XSLT(xslt)
  newdom = transform(dom)
  # not doing anything with infile, but it's there if you need to see it.
  print (xsET.tostring(newdom, pretty_print=True))
  print ("Formatting Complete...")

def main():
    try:
      args = sys.argv[1:]  
      #Boolean True if needed to map to legacy id instead of vul id
      if len(args) == 4 and args[0] == '-legacy':
        old_stig = args[1]
        new_stig = args[2]
        xsl_file = args[3]
        legacy   = True
       else:
        old_stig = args[0]
        new_stig = args[1]
        xsl_file = args[2]
        legacy   = False
        
    except IndexError:
      raise SystemExit(f"Usage: {sys.argv[0]} -legacy <old_STIG> <new_STIG> <xsl_format>")
    #print (sys.argv[::-1])
    # collect the comments for each vulnerability from the old stig
    data = []
    ckl = parse_xml(old_stig)  
    vuln_tag = ckl.getElementsByTagName('VULN')
    data = get_vulnerability_data(vuln_tag, data)
    write_to_XML(new_stig, data, legacy)
    formatCKL(new_stig, xsl_file)

if __name__ == '__main__':
    main()
