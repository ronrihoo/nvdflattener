# nvdflattener.py
import sys
import pandas as pd
import numpy as np
import json
import zipfile
from requests import get

# variables (general)
_year = 0

# variables for URLs
_url = "https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-{}.json.zip".format(_year)
urlComponent1 = "https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-"
urlComponent2 = ".json.zip"

# variables for file names (TODO: rename variables -- they don't look pleasant)
_zip_file_name = _url.split('/')[-1]
_file_name = _url.split('/')[-1][:-4]
_CSV_file_name = _file_name + ".csv"
NVD_COT_variables_file_name = "./CWE_over_time_slice"
NVD_COT_var_list_file_name = "NVD_COT_variables_list.txt"

# variables for help menu
flatten_commands = [ "-r", "run", "-f", "flatten"]
help_commands = [ "-h", "help" ]


# Command-Line


def actOnArgument():
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg in flatten_commands:
            if len(sys.argv) == 4:
                flatten(starting=sys.argv[2], ending=sys.argv[3])
            elif len(sys.argv) == 3:
                flattenOneYear(sys.argv[2])
            else:
                flatten()
        if arg in help_commands:
            showHelp()


# Help Menu


def showHelp():
    # TODO: requires more information and could use a conventional layout
    sys.stdout.write("nvdflattener\n" +
                "\trun - Process all NVD CVE data sets to collect CWE Over Time data.\n" + 
                "\thelp - Display this menu.\n\n")


# Download and Unzip File


def download(url, file_name):
    with open(file_name, "wb") as file:
        response = get(url)
        file.write(response.content)

        
def fixPath(path):
    if path[-1] != '/': 
        return path + "/"
    return path


def unzipFile(file_path, file_name):
    file_path = fixPath(file_path)
    with zipfile.ZipFile(file_path + file_name, "r") as zip_ref:
        zip_ref.extractall(file_path); # semicolon to hide output in Jupyter Notebook


# Parse


def getCveItemsFromFile(file_name):
    data_set = pd.read_json(file_name, orient='columns')
    cve_items = data_set['CVE_Items']
    return cve_items


def getAffected(item):
    ID = []
    vendors = []
    products = []
    versions = []
    version_ranges = []
    rows = 0
    # looks like an atrocious function -- O(n^3) -- but it's unlikely that there will ever
    # be more than one vendor; and there's usually only one product
    for i, vendor in enumerate(item['CVE_affects']['CVE_vendor']['CVE_vendor_data']):
        for j, product in enumerate(vendor['CVE_product']['CVE_product_data']):
            for k, version in enumerate(product['CVE_version']['CVE_version_data']):
                ID.append(item['CVE_data_meta']['CVE_ID'])
                vendors.append(vendor['CVE_vendor_name'])
                products.append(product['CVE_product_name'])
                versions.append(version['CVE_version_value'])
                version_ranges.append(version['CVE_version_affected'])
                rows = rows + 1
    if not ID:
        ID = ["null"]
    if not vendors:
        vendors = ["null"]
    if not products:
        products = ["null"]
    if not versions:
        versions = ["null"]
    if not version_ranges:
        version_ranges = ["null"]  
    return ID, vendors, products, versions, version_ranges, rows


def getProblemType(item, rows):
    """
        It's expected that there will only be one problemtype and, therefore, only
        one CWE value. So given that condition, copying it in multiple rows will work 
        out well.
        
        item: the CVE chunk from the NVD CVE JSON feed
        rows: the number of rows that the CVE_affected data produced for this CVE
        
        returns: a Python list of the CWE value copied `rows` times
    """
    CWE = []
    CWE1 = []
    CWE2 = []
    CWE3 = []
    for i, problemtype in enumerate(item['CVE_problemtype']['CVE_problemtype_data']):
        for j, description in enumerate(problemtype['description']):
                CWE.append(description['value'])
    while (len(CWE1) < rows):
        if (CWE and len(CWE) > 0): 
            CWE1.append(CWE[0]) 
        else: 
            CWE1.append(0)
        if (CWE and len(CWE) > 1): 
            CWE2.append(CWE[1]) 
        else: 
            CWE2.append(0)
        if (CWE and len(CWE) > 2): 
            CWE3.append(CWE[2]) 
        else: 
            CWE3.append(0)
    if not CWE1:
        CWE1 = ["null"]
    if not CWE2:
        CWE2 = ["null"]
    if not CWE3:
        CWE3 = ["null"]
    return CWE1, CWE2, CWE3


def getImpactCVSSv2(item, rows, ID):
    av = []
    ac = []
    au = []
    c = []
    i = []
    a = []
    score = []
    # empty CVE_impact data do exist (ex: nvdcve-1.0-2017.json, CVE_items[291 & 292])
    try:
        item = item['CVE_impact']['CVE_impact_cvssv2']['bm']
    except:
        zeroes = ([0 for x in range(rows)] if rows > 0 else [0])
        return (zeroes,)*7
    while(len(av) < rows):
        av.append(item['av'])
        ac.append(item['ac'])
        au.append(item['au'])
        c.append(item['c'])
        i.append(item['i'])
        a.append(item['a'])
        score.append(item['score'])
    if(rows == 0):
        av.append(item['av'])
        ac.append(item['ac'])
        au.append(item['au'])
        c.append(item['c'])
        i.append(item['i'])
        a.append(item['a'])
        score.append(item['score'])
    if not av:
        av = ["null"]
    if not ac:
        ac = ["null"]
    if not au:
        au = ["null"]
    if not c:
        c = ["null"]
    if not i:
        i = ["null"]
    if not a:
        a = ["null"]
    if not score:
        score = ["null"]
    return av, ac, au, c, i, a, score


def getImpactCVSSv3(item, rows):
    av = []
    ac = []
    pr = []
    ui = []
    scope = []
    c = []
    i = []
    a = []
    score = []
    # empty CVE_impact data do exist (ex: nvdcve-1.0-2017.json, CVE_items[291 & 292])
    try:
        item = item['CVE_impact']['CVE_impact_cvssv3']['bm']
    except:
        zeroes = ([0 for x in range(rows)] if rows > 0 else [0])
        return (zeroes,)*9
    while(len(av) < rows):
        av.append(item['av'])
        ac.append(item['ac'])
        pr.append(item['pr'])
        ui.append(item['ui'])
        scope.append(item['scope'])
        c.append(item['c'])
        i.append(item['i'])
        a.append(item['a'])
        score.append(item['score'])
    if(len(av) == 0):
        av.append(item['av'])
        ac.append(item['ac'])
        pr.append(item['pr'])
        ui.append(item['ui'])
        scope.append(item['scope'])
        c.append(item['c'])
        i.append(item['i'])
        a.append(item['a'])
        score.append(item['score'])
    if not av:
        av = ["null"]
    if not ac:
        ac = ["null"]
    if not pr:
        pr = ["null"]
    if not scope:
        scope = ["null"]
    if not c:
        c = ["null"]
    if not i:
        i = ["null"]
    if not a:
        a = ["null"]
    if not score:
        score = ["null"]
    return av, ac, pr, ui, scope, c, i, a, score


# Reshape and Clean


# n rows
def buildNewIndex(n):
    return np.array([np.arange(n)]).T # n row
    #return np.array([np.arange(n)]) # n columns

    
# n row, x columns
def buildNew2dIndex(n, x):
    return np.array([np.arange(n)]*x).T
    #return np.array([np.arange(n)]*x) # n columns, x rows


def newDataFrame(index, columns, filler):
    newDf = pd.DataFrame(index=index, columns=columns)
    newDf = newDf.fillna(filler)
    return newDf


def buildDataFrameB(na_filler = 0):
    index = buildNewIndex(0)
    columns = ['ID', 'vendor', 'product', 'version', 'version_range', 'CWE1', 'CWE2', 'CWE3',
              'CVSS_v2_av', 'CVSS_v2_ac', 'CVSS_v2_au', 'CVSS_v2_c', 'CVSS_v2_i',
              'CVSS_v2_a', 'CVSS_v2_score', 'CVSS_v3_av', 'CVSS_v3_ac', 'CVSS_v3_pr', 
              'CVSS_v3_ui', 'CVSS_v3_scope', 'CVSS_v3_c', 'CVSS_v3_i', 'CVSS_v3_a', 
              'CVSS_v3_score']
    data_frame = newDataFrame(index, columns, na_filler)
    return data_frame


def getCveDataWithImpactScores(cve_items):
    data = buildDataFrameB()
    x = len(cve_items)
    for i, cve in enumerate(cve_items):
        #print("{}: {}".format(_year, i))
        display = ("\r\x1b[K{}: {} / {}".format(_year, i, x) 
              if i < x else "\r\x1b[K\x1b[E{}: {} / {}".format(_year, i, x))
        sys.stdout.write(display)
        if i < (len(cve_items) - 1): sys.stdout.flush()
        else: sys.stdout.write("\n")
        IDs, vendors, products, versions, version_ranges, rows = getAffected(cve)
        CWE1, CWE2, CWE3 = getProblemType(cve, rows)
        av2, ac2, au2, c2, i2, a2, score2 = getImpactCVSSv2(cve, rows, IDs)
        av3, ac3, pr3, ui3, scope3, c3, i3, a3, score3 = getImpactCVSSv3(cve, rows)
        # extend rows (vertically)
        currentField = np.array([IDs, vendors, products, versions, version_ranges, 
                                 CWE1, CWE2, CWE3, av2, ac2, au2, c2, i2, a2, score2,
                                 av3, ac3, pr3, ui3, scope3, c3, i3, a3, score3]).T
        currentIndex = np.array([np.arange(len(currentField))]).T
        data = data.append(pd.DataFrame(currentField, currentIndex, data.columns), ignore_index=True)
        # fill columns (vertically, one column at a time)
        if i > 0:
            data['ID'] = data['ID'].append(pd.Series(IDs), ignore_index=True)
            data['vendor'] = data['vendor'].append(pd.Series(vendors), ignore_index=True)
            data['product'] = data['product'].append(pd.Series(products), ignore_index=True)
            data['version'] = data['version'].append(pd.Series(versions), ignore_index=True)
            data['version_range'] = data['version_range'].append(pd.Series(version_ranges), ignore_index=True)
            data['CWE1'] = data['CWE1'].append(pd.Series(CWE1), ignore_index=True)
            data['CWE2'] = data['CWE2'].append(pd.Series(CWE2), ignore_index=True)
            data['CWE3'] = data['CWE3'].append(pd.Series(CWE3), ignore_index=True)
            data['CVSS_v2_av'] = data['CVSS_v2_av'].append(pd.Series(av2), ignore_index=True)
            data['CVSS_v2_ac'] = data['CVSS_v2_ac'].append(pd.Series(ac2), ignore_index=True)
            data['CVSS_v2_au'] = data['CVSS_v2_au'].append(pd.Series(au2), ignore_index=True)
            data['CVSS_v2_c'] = data['CVSS_v2_c'].append(pd.Series(c2), ignore_index=True)
            data['CVSS_v2_i'] = data['CVSS_v2_i'].append(pd.Series(i2), ignore_index=True)
            data['CVSS_v2_a'] = data['CVSS_v2_a'].append(pd.Series(a2), ignore_index=True)
            data['CVSS_v2_score'] = data['CVSS_v2_score'].append(pd.Series(score2), ignore_index=True)
            data['CVSS_v3_av'] = data['CVSS_v3_av'].append(pd.Series(av3), ignore_index=True)
            data['CVSS_v3_ac'] = data['CVSS_v3_ac'].append(pd.Series(ac3), ignore_index=True)
            data['CVSS_v3_pr'] = data['CVSS_v3_pr'].append(pd.Series(pr3), ignore_index=True)
            data['CVSS_v3_ui'] = data['CVSS_v3_ui'].append(pd.Series(ui3), ignore_index=True)
            data['CVSS_v3_scope'] = data['CVSS_v3_scope'].append(pd.Series(scope3), ignore_index=True)
            data['CVSS_v3_c'] = data['CVSS_v3_c'].append(pd.Series(c3), ignore_index=True)
            data['CVSS_v3_i'] = data['CVSS_v3_i'].append(pd.Series(i3), ignore_index=True)
            data['CVSS_v3_a'] = data['CVSS_v3_a'].append(pd.Series(a3), ignore_index=True)
            data['CVSS_v3_score'] = data['CVSS_v3_score'].append(pd.Series(score3), ignore_index=True)
        else: 
            data['ID'] = pd.Series(IDs)
            data['vendor'] = pd.Series(vendors)
            data['product'] = pd.Series(products)
            data['version'] = pd.Series(versions)
            data['version_range'] = pd.Series(version_ranges)
            data['CWE1'] = pd.Series(CWE1)
            data['CWE2'] = pd.Series(CWE2)
            data['CWE3'] = pd.Series(CWE3)
            data['CVSS_v2_av'] = pd.Series(av2)
            data['CVSS_v2_ac'] = pd.Series(ac2)
            data['CVSS_v2_au'] = pd.Series(au2)
            data['CVSS_v2_c'] = pd.Series(c2)
            data['CVSS_v2_i'] = pd.Series(i2)
            data['CVSS_v2_a'] = pd.Series(a2)
            data['CVSS_v2_score'] = pd.Series(score2)
            data['CVSS_v3_av'] = pd.Series(av3)
            data['CVSS_v3_ac'] = pd.Series(ac3)
            data['CVSS_v3_pr'] = pd.Series(pr3)
            data['CVSS_v3_ui'] = pd.Series(ui3)
            data['CVSS_v3_scope'] = pd.Series(scope3)
            data['CVSS_v3_c'] = pd.Series(c3)
            data['CVSS_v3_i'] = pd.Series(i3)
            data['CVSS_v3_a'] = pd.Series(a3)
            data['CVSS_v3_score'] = pd.Series(score3)
        if i == (len(cve_items) - 1):
            return data


def makeCsvFile(data_frame, file_name):
    if file_name[-4:] != ".csv": 
        file_name += '.csv'
    data_frame.to_csv(file_name, sep=',', header=True)


def makeCsvFileWithoutIndex(data_frame, file_name):
    if file_name[-4:] != ".csv": 
        file_name += '.csv'
    data_frame.to_csv(file_name, sep=',', header=True, index=False)


def dropCveIdDuplicates(data_set):
    temp = data_set.drop_duplicates(subset=['ID'], inplace=False).reset_index()
    temp = temp.drop('index', axis = 1)
    return temp


def dropCweDuplicates(data_set):
    temp = data_set.drop_duplicates(subset=['CWE'], inplace=False).reset_index()
    temp = temp.drop('index', axis = 1)
    return temp


def dropProductDuplicates(data_set):
    temp = data_set.drop_duplicates(subset=['product'], inplace=False).reset_index()
    temp = temp.drop('index', axis = 1)
    return temp


def dropVendorDuplicates(data_set):
    temp = data_set.drop_duplicates(subset=['vendor'], inplace=False).reset_index()
    temp = temp.drop('index', axis = 1)
    return temp


def renameColumns(data, columns):
    data.columns = columns
    return data


def cleanData(data_set):
    df = data_set.drop('Unnamed: 0', axis=1)
    return df


def clearZeroesInOneColumn(data, column):
    data = pd.DataFrame(data[data[column] != '0'])
    data = pd.DataFrame(data[data[column] != 0])
    return data


def clearNullValuesInOneColumn(data, column):
    data = pd.DataFrame(data[data[column] != 'null'])
    return data


def splitOneColumn(data_set, oldColumnName, newColumnName):
    column = renameColumns(data_set[[oldColumnName]], [newColumnName])
    column = clearZeroesInOneColumn(column, newColumnName)
    return column


def splitTwoColumns(data_set, oldColumns, newColumns):
    partial_data = renameColumns(data_set[oldColumns], newColumns)
    partial_data = clearZeroesInOneColumn(partial_data, newColumns[0])
    partial_data = clearZeroesInOneColumn(partial_data, newColumns[1])
    partial_data = clearNullValuesInOneColumn(partial_data, newColumns[0]) # CWE
    return partial_data


def splitCweColumns(data_set):
    """
        The only use of this function is to be called by the checkResults() function.
    """
    cwe_1 = splitOneColumn(data_set, 'CWE1', 'CWE')
    cwe_2 = splitOneColumn(data_set, 'CWE2', 'CWE')
    cwe_3 = splitOneColumn(data_set, 'CWE3', 'CWE')
    return cwe_1, cwe_2, cwe_3


def splitAndMergeCweColumns(data_set):
    cwe_1 = splitOneColumn(data_set, 'CWE1', 'CWE')
    cwe_2 = splitOneColumn(data_set, 'CWE2', 'CWE')
    cwe_3 = splitOneColumn(data_set, 'CWE3', 'CWE')
    return pd.concat([cwe_1, cwe_2, cwe_3])


def splitAndMergeTwoColumnedSet(data_set, old1, old2, old3, new_col, base_col):
    set_1 = splitTwoColumns(data_set, [old1, base_col], [new_col, base_col])
    set_2 = splitTwoColumns(data_set, [old2, base_col], [new_col, base_col])
    set_3 = splitTwoColumns(data_set, [old3, base_col], [new_col, base_col])
    return pd.concat([set_1, set_2, set_3], ignore_index=True)


def getCweFrequencyCounts(cwe_set):
    cwe_freq = pd.value_counts(cwe_set['CWE'])
    return cwe_freq


def getCweFrequencyCountsForVendors(cwe_set):
    return pd.value_counts(cwe_set['vendor'])


def getCount(df, col, val):
    return df[df[col] == val].count()


def checkResults(data_set, cwe_list, column, CWE_ID):
    cwe_1, cwe_2, cwe_3 = splitCweColumns(data_set)
    a = getCount(cwe_1, column, CWE_ID)
    b = getCount(cwe_2, column, CWE_ID)
    c = getCount(cwe_3, column, CWE_ID)
    d = getCount(cwe_list, column, CWE_ID)
    return d == a + b + c


def performCweAssertions(data_set, cwe_list, column):
    """
        Optionally, another top-level function. Checks the integrity of the three CWE
        columns, ['CWE1', 'CWE2', 'CWE3'], merged under one column, ['CWE']. Uses 5
        values from the middle CWE column to find common CVE IDs. Column 'CVE3' is rarely
        used, so it's potentially left out; to ensure tests will occur.
        
        data_set: pandas.DataFrame - returned by dropCveIdDuplicates()
        cwe_list: pandas.DataFrame - returned by splitAndMergeCweColumns()
        column: string - the new column name, 'CWE'
        
        Returns: string - indicates whether assertions passed or failed.
    """
    values = cwe_2.drop_duplicates(column)[column][:5]
    for value in values:
        if not checkResults(data_set, cwe_list, column, value).bool():
            return "Failed (value: " + value + ")"
    return "Passed"


# Top-Level Functions


def downloadAndUnzip(url, zip_file_name):
	download(url, zip_file_name)
	unzipFile("./", zip_file_name)


def extractCveItems(file_name):
	cve_items = getCveItemsFromFile(file_name)
	return cve_items


def extractData(cve_items):
	data = getCveDataWithImpactScores(cve_items)
	return data


def clean(data):
	cleaned_data = dropCveIdDuplicates(data)
	return cleaned_data


def reshape(cleaned_data):
	cwe_list = splitAndMergeCweColumns(cleaned_data)
	return cwe_list


# Arbitrary Re-structuring (as needed for analysis)


# take CWE ID strings and replace them with CWE name strings
def nameCWEsInColumns(old_columns, CWEs):
    new_columns = []
    for column in old_columns:
        new_columns.append(CWEs[column])
    return new_columns


# enumerate and add values from list, just in case the values might exist in the future
def addLeftoverColumnsWithRows(df, additional_columns, values_list):
    for i, element in enumerate(additional_columns):
        df.insert(len(df.columns), element, values_list[i])


def getVendorAndCwe(df):
	vendor_cwe = splitAndMergeTwoColumnedSet(df, 'CWE1', 'CWE2', 'CWE3', 'CWE', 'vendor')
	# 'total' goes at the beginning of CSV file, after the column names line
	final = pd.crosstab(vendor_cwe['CWE'], vendor_cwe['vendor'])
	total = (final.T.sum())
	total = pd.DataFrame(total, columns=['total'])
	total = total.T.append(final.T)
	return total


def readListFromFile(file_name):
    data = ""
    with open(file_name) as data_file:
        data = data_file.read()
    data = data[1:-2].replace("'", "").split(", ")
    del data[0]
    return data


def writeListToFile(items, file_name):
    with open(file_name, "w") as data_file:
        data_file.write(str(items))


def buildNvdCweList(NVD_COT_variables_file_name):
	CWEs = {}
	CWEs_rev = {}
	CWE_columns = []
	columns_str = ""
	data = ""
	with open(NVD_COT_variables_file_name) as data_file:
	    data = data_file.read()
	lines = data.split("\n")
	del lines[-1] # last one is a blank string, ""
	for line in lines:
	    line = line.split(" - ")
	    CWEs[(line[0] if "NVD" in line[0] else "CWE-" + line[0])] = line[1]
	    CWEs_rev[line[1]] = (line[0] if "NVD" in line[0] else "CWE-" + line[0])
	    CWE_columns.append(line[1])
	    columns_str += line[1] + ","
	# remove the last comma -- lazy coding
	columns_str = columns_str[:len(columns_str) - 1]
	return CWEs, CWEs_rev, CWE_columns, columns_str, data


def replaceCweColumnsId(df, NVD_COT_variables_file_name):
	data = ""
	years = []
	total = getVendorAndCwe(df)
	CWEs, CWEs_rev, CWE_columns, columns_str, data = buildNvdCweList(NVD_COT_variables_file_name)
	for n in range(2, 18):
	    years.append("20" + ("0" +str(n) if n < 10 else str(n)))
	# columns acquired through parsing the data sets
	data_columns = total.columns
	# columns obtained from NVD's CWE Over Time visualization
	NVD_columns = CWEs
	# columns that exist in both lists and, therefore, will be kept for modifying the data set
	kept_columns = list(set(list(total.columns)).intersection(list(CWEs)))
	df = pd.DataFrame(total[kept_columns])
	# columns that NVD's CWE Over Time visualization uses
	NVD_CWE_name_columns = []
	for cwe in NVD_columns:
	    NVD_CWE_name_columns.append(CWEs[cwe])
	# CWE names (instead of CWE IDs)
	CWE_name_columns = []
	for column in df.columns:
	    CWE_name_columns.append(CWEs[column])
	# columns that are still left from the NVD CWE list
	left_over_columns = list(set(NVD_columns) - set(kept_columns))
	list_of_zeroes = list((pd.Series(np.array((0,)*len(df.index)),  index=df.index)*len(left_over_columns)))
	addLeftoverColumnsWithRows(df, left_over_columns, list_of_zeroes)
	named_columns = nameCWEsInColumns(df.columns, CWEs)
	df = renameColumns(df, named_columns);
	return df, CWE_columns


def reorderColumns(df, CWE_columns):
	del CWE_columns[0]
	df = df[CWE_columns]
	return df


def runAll(url, zip_file_name, file_name, CSV_file_name, NVD_COT_variables_file_name):
    downloadAndUnzip(url, zip_file_name)
    cve_items = extractCveItems(file_name)
    data = extractData(cve_items)
    makeCsvFileWithoutIndex(data, file_name + ".csv")
    df = clean(data)
    cwe_list = reshape(df)
    df, CWE_columns = replaceCweColumnsId(df, NVD_COT_variables_file_name)
    df = reorderColumns(df, CWE_columns)
    df.columns.name = "VENDOR"
    makeCsvFile(df, CSV_file_name)
    return df


def getTotalRow(df):
    return list(df.T['total'])


def makeUrlList(start, end):
    urls = []
    for n in range(start, end):
        year = ("20" + ("0" + str(n) if n < 10 else str(n)))
        urls.append(urlComponent1 + year + urlComponent2)
    return urls


def makeYearList(starting, ending):
    return [x for x in range(int(starting), int(ending))]


def insertRow(df, year, values):
    df = df.T
    df.insert(len(df.columns), year, values[df.T.columns].T)
    df = df.T
    return df


def insertRows(df, years, values):
    for i, year in enumerate(years):
        df.insert(len(df.columns), year, values[i])
    return df


def makeDataFrame(columns):
    data_frame = pd.DataFrame(pd.np.empty((0, len(columns))))
    data_frame.columns = columns
    return data_frame


def makeDataFrameForTotals(columns, years, values):
    data_frame = pd.DataFrame(pd.np.empty((0, len(columns))))
    data_frame.columns = columns
    data_frame = insertRows(data_frame.T, years, values)
    return data_frame.T


def run(argUrl):
    return runAll(argUrl, _zip_file_name, _file_name, _CSV_file_name, NVD_COT_variables_file_name)


def updateGlobalVariables(year, url):
    global _year, _url, _zip_file_name, _file_name, _CSV_file_name
    _year = year
    _url = url
    _zip_file_name = url.split('/')[-1]
    _file_name = url.split('/')[-1][:-4]
    _CSV_file_name = str(year) + "-NVD-CWE-vs-vendors.csv"


def flatten(starting="2002", ending="2017"):
    years = makeYearList(int(starting), int(ending) + 1)
    sys.stdout.write("Year  CVE #\n")
    for i, url in enumerate(makeUrlList(int(starting[2:]), int(ending[2:]) + 1)):
        updateGlobalVariables(years[i], url)
        run(url)


def flattenOneYear(year="2017"):
    sys.stdout.write("Year  CVE #\n")
    url = makeUrlList(int(year) % 100, int(year) % 100)
    updateGlobalVariables(year, url)
    run(url)
