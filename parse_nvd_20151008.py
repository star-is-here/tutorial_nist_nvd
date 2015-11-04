# Parsing NVDCVE XML files

import xml.etree.ElementTree as et, re, pprint, csv, json, datetime
from fuzzywuzzy import process
from tqdm import *
from multiprocessing import Pool

pp = pprint.PrettyPrinter(indent=2)

def pull_nvd(fname):
    print 'Loading NVD Dataset: %s'%fname
    nvd_dict = {}
    with open(fname) as f:
        for ln in tqdm(f):
            if 'entry id=' in ln:
                vuln_id = re.search('CVE.\d\d\d\d.\d\d\d\d', ln).group(0)
                # print '************************%s************************'%vuln_id
                nvd_dict[vuln_id] = {}
            elif 'cpe-lang:fact-ref name=' in ln:
                nvd_dict[vuln_id]['vuln_os'] = []
                nvd_dict[vuln_id]['vuln_os_plat'] = []
                vuln_os = re.search('\".*\"', ln).group(0)[8:-1]
                vuln_os_plat = re.split('[:\"]', ln)
                # print '--->%s'%vuln_os
                nvd_dict[vuln_id]['vuln_os'].append(re.sub('_',' ',vuln_os_plat[4]))
                nvd_dict[vuln_id]['vuln_os_plat'].append(re.sub('_',' ',vuln_os_plat[4])+' '+re.sub('_',' ',vuln_os_plat[5]))
            elif '<vuln:published-datetime>' in ln:
                vuln_date = re.search('\d\d\d\d.*<', ln).group(0)[:-1]
                date = [int(vuln_date[0:4]),int(vuln_date[5:7]),int(vuln_date[8:10]), int(vuln_date[11:13]), int(vuln_date[14:16]), int(vuln_date[17:19])]
                date_num = datetime.date(date[0],date[1],date[2]).isocalendar()
                datetime_num = datetime.datetime(date[0],date[1],date[2],date[3],date[4],date[5]).strftime('%Y%m%d %X')
                # print '    --->%s'%vuln_date
                nvd_dict[vuln_id]['vuln_date'] = date_num
                nvd_dict[vuln_id]['vuln_datetime'] = datetime_num
            elif '<cvss:score>' in ln:
                vuln_score = re.search('\d?\d.\d', ln).group(0)
                # print '    --->%s'%vuln_score
                nvd_dict[vuln_id]['vuln_score'] = vuln_score
            elif '<cvss:access-vector>' in ln:
                vuln_vector = re.search('>.*<', ln).group(0)[1:-1]
                # print '    --->%s'%vuln_vector
                nvd_dict[vuln_id]['vuln_vector'] = vuln_vector
            elif '<cvss:access-complexity>' in ln:
                vuln_compl = re.search('>.*<', ln).group(0)[1:-1]
                # print '    --->%s'%vuln_compl
                nvd_dict[vuln_id]['vuln_compl'] = vuln_compl
            elif '<cvss:authentication>' in ln:
                vuln_auth = re.search('>.*<', ln).group(0)[1:-1]
                # print '    --->%s'%vuln_auth
                nvd_dict[vuln_id]['vuln_auth'] = vuln_auth
            elif '<cvss:confidentiality-impact>' in ln:
                vuln_confid = re.search('>.*<', ln).group(0)[1:-1]
                # print '    --->%s'%vuln_confid
                nvd_dict[vuln_id]['vuln_confid'] = vuln_confid
            elif '<cvss:integrity-impact>' in ln:
                vuln_integ = re.search('>.*<', ln).group(0)[1:-1]
                # print '    --->%s'%vuln_integ
                nvd_dict[vuln_id]['vuln_integ'] = vuln_integ
            elif '<cvss:availability-impact>' in ln:
                vuln_avail = re.search('>.*<', ln).group(0)[1:-1]
                # print '    --->%s'%vuln_avail
                nvd_dict[vuln_id]['vuln_avail'] = vuln_avail
            elif 'vuln:reference href=' in ln:
                vuln_link = re.search('href=.*\"', ln).group(0)[6:-1]
                # print '    --->%s'%vuln_link
                nvd_dict[vuln_id]['vuln_link'] = vuln_link
            elif '<vuln:summary>' in ln:
                vuln_summ = re.search('>.*<', ln).group(0)[1:-1]
                # print '    --->%s'%vuln_summ
                nvd_dict[vuln_id]['vuln_summ'] = vuln_summ
            elif '<vuln:source>' in ln:
                vuln_source = re.search('>.*<', ln).group(0)[1:-1]
                # print '    --->%s'%vuln_summ
                nvd_dict[vuln_id]['vuln_source'] = vuln_source
    return(nvd_dict)

# def pull_dict(fname):
#     plat_list = []
#     with open(fname) as f:
#         for ln in f:
#             if 'Vendor website' in ln:
#                 # print ln
#                 vend_web = re.search('http[s]*\:\/\/.*\.[A-Za-z0-9]*',ln)
#                 # print vend_web.group()
#                 plat_list.append(vend_web.group(0))
#     return(plat_list)

# Pull dictionary definitions
# nvd_dict = pull_dict('./official-cpe-dictionary_v2.3.xml')

# Pull NVD dataset
nvd = pull_nvd('./nvdcve-2.0-2015.xml')

# Create timeline of 2015
nvd_timeline = [[],[]]
for cve in tqdm(nvd.keys()):
    if 'vuln_score' in nvd[cve].keys():
        weightedme = {'Method':'Weighted', 'Date':nvd[cve]['vuln_datetime'], 'Value':float(nvd[cve]['vuln_score'])}
        countme = {'Method':'Count', 'Date':nvd[cve]['vuln_datetime'], 'Value':1}
        if nvd[cve]['vuln_datetime'] not in [ x['Date'] for x in nvd_timeline[0] ]:
            nvd_timeline[0].append(weightedme)
            nvd_timeline[1].append(countme)
        else:
            for i, day in enumerate(nvd_timeline[0]):
                if nvd[cve]['vuln_datetime'] in day['Date'] and day['Method'] == 'Weighted':
                    nvd_timeline[0][i]['Value'] += float(nvd[cve]['vuln_score'])
                elif nvd[cve]['vuln_datetime'] in day['Date'] and day['Method'] == 'Count':
                    nvd_timeline[1][i]['Value'] += 1

# Export to json
with open('./nvd_timeline.json', 'wb') as f:
    json.dump(nvd_timeline, f)

# Count vulnerabilities per platform
nvd_plat = []
for cve in tqdm(nvd.keys()):
    if 'vuln_score' in nvd[cve].keys():
        for os in nvd[cve]['vuln_os']:
            appendme = [os, 1]
            if os not in [ x[0] for x in nvd_plat ]:
                nvd_plat.append(appendme)
            else:
                for i, plat in enumerate(nvd_plat):
                    if os == plat[0]:
                        nvd_plat[i][1] += 1

nvd_plat_sort = [['plat','count']]
nvd_plat_sort.extend(sorted(nvd_plat))

with open('./nvd_plat.csv', 'wb') as csvfile:
    writeme = csv.writer(csvfile, delimiter=',')
    writeme.writerows(nvd_plat_sort)

# Update with other years
# nvd.update(pull_nvd('./nvdcve-2.0-2002.xml'))
# nvd.update(pull_nvd('./nvdcve-2.0-2003.xml'))
# nvd.update(pull_nvd('./nvdcve-2.0-2004.xml'))
# nvd.update(pull_nvd('./nvdcve-2.0-2005.xml'))
# nvd.update(pull_nvd('./nvdcve-2.0-2006.xml'))
# nvd.update(pull_nvd('./nvdcve-2.0-2007.xml'))
# nvd.update(pull_nvd('./nvdcve-2.0-2008.xml'))
# nvd.update(pull_nvd('./nvdcve-2.0-2009.xml'))
# nvd.update(pull_nvd('./nvdcve-2.0-2010.xml'))
nvd.update(pull_nvd('./nvdcve-2.0-2011.xml'))
nvd.update(pull_nvd('./nvdcve-2.0-2012.xml'))
nvd.update(pull_nvd('./nvdcve-2.0-2013.xml'))
nvd.update(pull_nvd('./nvdcve-2.0-2014.xml'))

nvd_timeline_five = []
for cve in tqdm(nvd.keys()):
    if 'vuln_score' in nvd[cve].keys():
        appendme = [nvd[cve]['vuln_date'][1],0,0,0,0,0]
        if nvd[cve]['vuln_date'][0] == 2015:
            colnum = 1
        elif nvd[cve]['vuln_date'][0] == 2014:
            colnum = 2
        elif nvd[cve]['vuln_date'][0] == 2013:
            colnum = 3
        elif nvd[cve]['vuln_date'][0] == 2012:
            colnum = 4
        elif nvd[cve]['vuln_date'][0] == 2011:
            colnum = 5
        if nvd[cve]['vuln_date'][1] not in [ x[0] for x in nvd_timeline_five ]:
            # appendme[colnum] += float(nvd[cve]['vuln_score'])
            appendme[colnum] += 1
            nvd_timeline_five.append(appendme)
        else:        
            for i, day in enumerate(nvd_timeline_five):
                if nvd[cve]['vuln_date'][1] == day[0]:
                    # nvd_timeline_five[i][colnum] += float(nvd[cve]['vuln_score'])
                    nvd_timeline_five[i][colnum] += 1
                # nvd_timeline_five[i][4] += 1

nvd_timeline_five_sort = [['week','2015','2014','2013','2012','2011']]
nvd_timeline_five_sort.extend(sorted(nvd_timeline_five))

with open('./nvd_timeline_five.csv', 'wb') as csvfile:
    writeme = csv.writer(csvfile, delimiter=',')
    writeme.writerows(nvd_timeline_five_sort)

# # create Node-Edge JSON
# nvd_json = {'nodes':[],'links':[]}
# for cve in nvd.keys():
#     if 'vuln_os' in nvd[cve].keys():
#         append_vuln = {'name':cve, 'group':nvd[cve]['vuln_date'][2], 'week':nvd[cve]['vuln_date'][1], 'threat':float(nvd[cve]['vuln_score']), 'type':1}
#         nvd_json['nodes'].append(append_vuln)
#         for os in nvd[cve]['vuln_os']:
#             append_plat = {'name':os, 'group':nvd[cve]['vuln_date'][2], 'week':nvd[cve]['vuln_date'][1], 'threat':0, 'type':0}
#             if append_plat not in nvd_json['nodes']:
#                 nvd_json['nodes'].append(append_plat)
#             nvd_json['links'].append({'source':cve, 'target':os, 'group':nvd[cve]['vuln_date'][2], 'week':nvd[cve]['vuln_date'][1], 'threat':float(nvd[cve]['vuln_score'])})

# # Export to json
# with open('./nvd.json', 'wb') as f:
#     json.dump(nvd_json, f)

# # # Build exact edge list
# nvd_edge = [['source','target','value']]
# for cve in nvd.keys():
#     if 'vuln_score' in nvd[cve].keys():
#         threat = nvd[cve]['vuln_score']
#     else:
#         threat = 0.0
#     if 'vuln_os_plat' in nvd[cve].keys():
#         cve_type = (nvd[cve]['vuln_vector'], nvd[cve]['vuln_compl'], nvd[cve]['vuln_auth'], nvd[cve]['vuln_confid'], nvd[cve]['vuln_integ'])
#         for plat in nvd[cve]['vuln_os_plat']:
#             appendme = [cve_type, plat, threat]
#             if appendme not in nvd_edge:
#                 nvd_edge.append(appendme)

# # # Build exact node list
# nvd_node = [['id','value','type']]
# for row in nvd_edge:
#     append_vuln = [row[0],row[2],0]
#     append_targ = [row[1],0.0,1]
#     if append_vuln not in nvd_node:
#         nvd_node.append(append_vuln)
#     if append_targ not in nvd_node:
#         nvd_node.append(append_targ)

# # Export to CSV for Gephi
# with open('./nvd_edge.csv', 'wb') as csvfile:
#     writeme = csv.writer(csvfile, delimiter=',')
#     writeme.writerows(nvd_edge)

# with open('./nvd_node.csv', 'wb') as csvfile:
#     writeme = csv.writer(csvfile, delimiter=',')
#     writeme.writerows(nvd_node)


# print 'Creating Software Schema'
# software_schema = {}
# with open('./Software.json') as f:
#     software_list = json.load(f)
#     for software in tqdm(software_list[u'instances']):
#         label = software.keys()[0]
#         if u'video game' not in software[label][u'http://www.w3.org/1999/02/22-rdf-syntax-ns#type_label'] and u'Game engine' not in software[label][u'http://dbpedia.org/ontology/genre_label'] and u'3D computer graphics' not in software[label][u'http://dbpedia.org/ontology/genre_label'] and u'Video game console emulator' not in software[label][u'http://dbpedia.org/ontology/genre_label'] and u'Project Genoa' not in software[label][u'http://www.w3.org/2000/01/rdf-schema#label'] and u'Tulip (python project)' not in software[label][u'http://www.w3.org/2000/01/rdf-schema#label']:
#                 dbname = software[label][u'http://www.w3.org/2000/01/rdf-schema#label']
#                 software_schema[dbname] = {}
#                 software_schema[dbname]['dbblurb'] = software[label][u'http://www.w3.org/2000/01/rdf-schema#comment']
#                 software_schema[dbname]['dbtype'] = software[label][u'http://www.w3.org/1999/02/22-rdf-syntax-ns#type_label']
#                 software_schema[dbname]['dbgenre'] = software[label][u'http://dbpedia.org/ontology/genre_label']

# null_schema = {'dbblurb':None, 'dbtype':None, 'dbgenre':None}

# def find_schema(search_term):
#     match = process.extractOne(search_term, software_schema.keys())
#     print 'Searching for\t\t\t\t%s'%search_term
#     print 'Found\t\t\t\t\t%s\nscore:\t\t%s'%(match[0], match[1])
#     if match[1] >= 90:
#         return [search_term, software_schema[match[0]]]
#     else:
#         return [search_term, null_schema]

# def find_schema_faster(procnumb, plat_list):
#     p = Pool(processes=procnumb)
#     return p.map(find_schema, plat_list)

# nvd_list = [ x[1] for x in nvd_edge[1:] ]

# nvd_schema = find_schema_faster(4, nvd_list)

# tag_edges = [['source','target','value']]
# for i, edge in enumerate(nvd_edge):
#     tags = []
#     if nvd_schema[i][1]['dbgenre'] != u'NULL' and nvd_schema[i][1]['dbgenre'] != None:
#         tags.extend(nvd_schema[i][1]['dbgenre'])
#     if nvd_schema[i][1]['dbtype'] != None:
#         tags.extend(nvd_schema[i][1]['dbtype'])
#     extendme = [ [edge[0],x,edge[2]] for x in tags ]
#     tag_edges.extend(extendme)

# with open('./tag_edges.csv', 'wb') as csvfile:
#     writeme = csv.writer(csvfile, delimiter=',')
#     writeme.writerows(list(set(tag_edges)))

