
**CrackQ_client: REST API client for CrackQ**
------------------------
-------
**INSTALLATION**
-----------------
*git clone https://github.com/f0cker/crackq_client.git*

*cd ./crackq_client*

*pip3 install .*

Or install from PyPi with:

*pip3 install crackq_client*

This will install the package, providing the client ('crackq') in your path.

-------
**USER GUIDE**
--------------------
To use the queue a Python client is provided.

Authentication is performed using a JSON post.

Some example uses are outlined below:

-------
**Auth**

login:

*crackq --url https://crackq.xxx.com -l --user test --passwd test*

or enter the password securely with a prompt:

*crackq --url https://crackq.xxx.com -l --user test*

logout:

*crackq --url https://crackq.xxx.com -L*

-------

**Queries**

view available Hashcat options (rules, wordlists, hash modes etc):

*crackq --url https://crackq.xxx.com -o*

query the queue:

*crackq --url https://crackq.xxx.com -q*
 
query failed queue:

*crackq --url https://crackq.xxx.com -f*
 
get details for a job:
 
*crackq --url https://crackq.xxx.com -j --job_id f210b58b7a214d33813051a550cbf3e4*

query complete queue:

*crackq --url https://crackq.xxx.com -c*

-------

**Actions**

add jobs:

wordlist/rules:

*crackq -a --attack_mode 0 --hash_mode 1000 --hash_file deadbeef.hashes --wordlist tw_leaks --url https://crackq.xxx.com --rules d3ad0ne --name dt_test_nt_twl_d3ad*

brute force:
 
*crackq -a --attack_mode 3 --hash_mode 1000 --hash_file deadbeef.hashes --mask ?u?a?a?l?l?l?a?a --url https://crackq.xxx.com --name dt_test_nt_brute*

stop/pause a job:

*crackq --url https://crackq.xxx.com -s --job_id <job_id uuid>*

stop/delete a job:

*crackq --url https://crackq.xxx.com -d --job_id <job_id uuid>*

restore a job:

*crackq --url https://crackq.xxx.com -r --job_id <job_id uuid>*

