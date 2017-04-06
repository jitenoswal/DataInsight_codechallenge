import pandas as pd
import numpy as np
from pandas.compat import StringIO
from pandas import HDFStore
import io
import time
import os
from dateutil import parser
from datetime import datetime
import udatetime as udatetime
from collections import OrderedDict
import hashlib

input_filename = 'log.txt'
input_path = os.path.join('../log_input', input_filename)

output_folder = '../log_output'
hosts_output_path = os.path.join(output_folder, 'hosts.txt')
resources_output_path = os.path.join(output_folder, 'resources.txt')
hours_output_path = os.path.join(output_folder, 'hours.txt')
blocked_output_path = os.path.join(output_folder, 'blocked.txt')

test_filename = 'sample_log.txt'
test_filename_path = os.path.join('~/Downloads', test_filename)


pd.set_option('io.hdf.default.format', 'table')

#print (input_path1)

def validate_and_pythonize(input_filepath):
	input_filepath_str = input_filepath.replace('.','_').replace('~','_')
	if ( not (os.path.isfile('storage.h5'))):
		hdf_store = HDFStore('storage.h5')
		print ('\n -- hdfs store created for awesomeness! ')
		df_logfile =  input_file(input_filepath)	
#		print ("\n df logfile created and first entry added: {}".format(df_logfile.head(4)))
		hdf_store[input_filepath_str] = df_logfile
		hdf_store.close()
		return df_logfile
	else:
		hdf_store = HDFStore('storage.h5')
		if(input_filepath_str in hdf_store):
			print ('\n -- hdfs store has this file already :) not wasting time again')
			print ("\n -- df logfile retrieved from store! ")
			df_logfile = hdf_store[input_filepath_str]
			hdf_store.close()
			return df_logfile
		else:
			print ('\n -- hdfs store doesn\'t have this file :( no worries optimizing behavior for future')
			df_logfile =  input_file(input_filepath)	
			print ("\n -- df logfile added to our hdfs store!")
			hdf_store[input_filepath_str] = df_logfile
			hdf_store.close()
			return df_logfile



def input_file(input_path):
	start_time = time.time()
	try:
		df = pd.read_csv(input_path, sep=r'\s* - - \[(\d\d/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}) (-\d{4})\] \"(.*)\" (.*) ', parse_dates=['date'], infer_datetime_format=True,engine='python', 
								names=['host', 'date', 'tzone', 'resource', 'http', 'byte'])
		print("\n--- %s seconds for Read in DataFrame --- \n\n" % (time.time() - start_time))
		print ('Length of DataFrame: ' + str(len(df)))
	#	df = df.convert_objects(convert_numeric=True).dropna()
		start_time = time.time()
		df = df.dropna()
		df = df.replace('-','0')
		df['byte'] = pd.to_numeric(df['byte'])
		df_pythonized = cleanDateData(df)
		print("\n--- %s seconds for Cleaning Date field and replacing null/- with 0 --- \n\n" % (time.time() - start_time))
		return df_pythonized
	except NameError:
		print ("File Not Found.") 
	except Exception as e:
		print ("Error in reading", base_file)
		print (e)
	return pd.DataFrame()


def convert_to_datetime(row):
    return pd.to_datetime(row.date, infer_datetime_format=True, format="%d/%b/%Y:%H:%M:%S").tz_localize(row.tzone)

def cleanDateData(df):
	tz_text = OrderedDict([('-400', 'US/Eastern'),('0000', 'GMT')])
	print (' ------ Clean date time data ------- ')
	start_time = time.time()
	df['tzone'].replace({-400: 'US/Eastern'}, regex=True, inplace=True)
#	df['to_datetime'] = df.apply(convert_to_datetime, axis=1)
	df['to_datetime'] = pd.DatetimeIndex(pd.to_datetime(df['date'], infer_datetime_format=True, format="%d/%b/%Y:%H:%M:%S")).tz_localize('UTC').tz_convert('US/Eastern')
	df = df.drop(['date','tzone'], axis=1)
	return df

def maxHostnameCount(df):
	start_time = time.time()
	count1 = df.groupby(['host'], sort=False).size().nlargest(10).reset_index(name='top10')
	print ("\n--- %s seconds for Groupby on Hostname Count ---\n" % (time.time() - start_time))
	print ("\n Answer 1: Max host count: \n\n{}".format(count1))
	count1.to_csv(hosts_output_path, index=False)

def maxResourceUsageQuery(df):
	start_time = time.time()
	df = df.drop(['http'], axis=1)
	count3 = df.groupby(by=['resource'], sort=False).sum().sort_values('byte',ascending=False).head(10)
	#count2 = df.groupby(['resource'], sort=False)['byte'].replace('-',0).agg(np.sum(['byte']))
	print ("\n--- %s seconds for Groupby on Resource Sum ---" % (time.time() - start_time))
	print("\n Answer 2: Max resource usage query \n{}".format(count3))
	count3.to_csv(resources_output_path)

def string_to_date(temp_row):
	return parser.parse(temp_row['date'].replace(':',' ', 1))

def total_nulls_in_dataset(df):
	start_time = time.time()
	df = pd.DataFrame({'host':[1,2,np.nan], 'resource':[np.nan,1,np.nan]})
	print ("\n Total number of nulls: \n")
	print (df.isnull().sum())
	print ("\n--- %s seconds Total number of nulls in dataset ---\n" % (time.time() - start_time))

def mostVisitedSiteRolling60min(df):
	print (' ------ Most visited in 60m rolling time ------- ')
	df = df.set_index('to_datetime')
	df = df.drop(['http','byte','resource'], axis=1)
	df['period'] = df.index.floor('60Min')
	start_time = time.time()
	df_60m = df.groupby(['period']).size().nlargest(10).reset_index(name='top10')	
	print("\n Answer 3: Post grouping period and host wise \n{}".format(df_60m.head(10)))
	print ("\n--- %s seconds post grouping period and host wise ---\n" % (time.time() - start_time))
	df_60m.to_csv(hours_output_path, index=False)

def detect3LoginFailure (df):
	print (' ------ Calculating: 3 login failure ------- ')
	http_code = OrderedDict([('200', 0),
            ('401', 1),
            ('403', 1)])
#	df.index = pd.DatetimeIndex(df.to_datetime)
	df = df.query('http in (401, 200)')
	print ('\nlength of 401/200 dataframe: ' + str(len(df)))
	print ('\nlength of 401 dataframe: ' + str(len(df.query('http == 401'))))
	df['code'] = (df['http'] == 401).astype(int)
	df = df.drop(['byte','resource', 'http'], axis=1)
	print (df.head(5))
#	df = df.groupby(['host'])
	df.head(10).to_csv(blocked_output_path, index=False)
	start_time = time.time()
	print ("\n-- Executing transformations --")
#	df['block_list'] = df.code.groupby((df.code != df.code.shift()).cumsum()).cumsum()
#	df_result = df['block_list'].size().nlargest(10).reset_index(name='top10')
# another transformation goes here	
	print("\n Answer 4: Block list with execessive access \n{}")
	print ("\n--- %s seconds for generating the blocklist ---\n" % (time.time() - start_time))
	

def find_unique_value(df):
	start_time = time.time()
	print("\n Unique Value ['http'] : " + str(pd.unique(df.http.ravel())))
	print("\n Unique Value ['resource'] : " + str(len(pd.unique(df.resource.ravel()))))
	print("\n Unique Value ['host'] : " + str(len(pd.unique(df.host.ravel()))))
	print ("\n--- %s seconds Time was take to calculate finding uniques ---" % (time.time() - start_time))


#input_df = input_file(input_path1)
start_time = time.time()
print ('\n---- Validate and Pythonizing your log file ----')
df_logfile = validate_and_pythonize(input_path)
print ("\n---- %s seconds Time taken for preparing your clean and pretty dataframe --- \n" % (time.time() - start_time))
find_unique_value(df_logfile)
maxHostnameCount(df_logfile)
maxResourceUsageQuery(df_logfile)
total_nulls_in_dataset(df_logfile)
mostVisitedSiteRolling60min(df_logfile)
detect3LoginFailure(df_logfile)
