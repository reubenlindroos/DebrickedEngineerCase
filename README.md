## Data Engineering Case @Debricked

In order to update the data.db file, which this api uses, please run
	
	python data_handler.py data.json

from the root directory and press 'y' when prompted. There are no POST or PUT methods defined 
in the API. To launch the flask website please run 

	python api.py

Examples of urls for both endpoints: 

	http://127.0.0.1:5000/cpe?vendor=redhat&product=enterprise_linux
	http://127.0.0.1:5000/cve?id=CVE-2019-10183