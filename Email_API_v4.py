from gevent import httplib, Greenlet, monkey; monkey.patch_all()
from gevent.pywsgi import WSGIServer
import gevent
try:
    import cPickle as pickle
except:
    import pickle

from APIlib.ldapuser import User
usertools = User()

import web
import json
import hashlib
import time
from pprint import pprint
from urlparse import parse_qs, parse_qsl

#ad_user = 'postmaster@ming.vn'
#ad_pass = 'farcry123'
url = {}
url['login'] = 'https://mail.ming.vn/API/login'
url['create_user'] = 'https://mail.ming.vn/API/create/user'
url['logout'] = 'https://mail.ming.vn/API/logout'
url['update'] = 'https://mail.ming.vn/API/profile/user/password/'
mail_quota = 1000 # MB
SECRET = {'ming.vn': '3f94hyl84j6g1lf149'}

KYOTO_HOST_MAILDIR = '192.168.5.61'
KYOTO_PORT_MAILDIR = 1978

KYOTO_HOST_COUNTMAIL = '192.168.5.61'
KYOTO_PORT_COUNTMAIL = 1979


def validate_data(domain, username, unverified_token):
    #print domain
    data = str(username) + SECRET[domain]
    token = hashlib.md5(data).hexdigest()
    if token == unverified_token:
        return True
    else:
        return False

def create_ldap_user(domain,username,password):
    import httplib2
    import urllib
    http = httplib2.Http(disable_ssl_certificate_validation=True)
    # Login
    params = urllib.urlencode({'username':ad_user, 'password':ad_pass})
    headers = {'Content-type': 'application/x-www-form-urlencoded'}
    response, content = http.request(url['login'],'POST',headers=headers,body=params)
    try:
        msg = parse_qsl(response['content-location'])[0][1]
        print "Admin login with error msg:", msg
        web.header('Content-Type', 'application/json')
        #return json.dumps(msg)
        return json.dumps({'return_code':msg})
    except KeyError:
        print "Login successful!"
        # Create ldap user:
        headers = {'Cookie': response['set-cookie']}
        pprint(headers)
        userparams = urllib.urlencode({'username':username, 'domainName':domain, 'newpw':password, 'confirmpw':password, 'mailQuota':mail_quota})
        response, content = http.request(url['create_user'],'POST',headers=headers,body=userparams)
	print response
        msg = parse_qsl(response['content-location'])[0][1]
        #response, content = http.request('https://mail.ming.vn/API/logout','GET')
        web.header('Content-Type', 'application/json')
        #return json.dumps(msg)
        return json.dumps({'return_code':msg})

def update_ldap_user(domain,username,password):
    import httplib2
    import urllib
    http = httplib2.Http(disable_ssl_certificate_validation=True)
    # Login
    params = urllib.urlencode({'username':ad_user, 'password':ad_pass})
    headers = {'Content-type': 'application/x-www-form-urlencoded'}
    response, content = http.request(url['login'],'POST',headers=headers,body=params)
    try:
        msg = parse_qsl(response['content-location'])[0][1]
        print "Admin login with error msg:", msg
        web.header('Content-Type', 'application/json')
        #return json.dumps(msg)
        return json.dumps({'return_code':msg})
    except KeyError:
        print "Login successful!"
        # Create ldap user:
        headers = {'Cookie': response['set-cookie']}
        pprint(headers)
        userparams = urllib.urlencode({'newpw':password, 'confirmpw':password})
        url_update_pw = url['update'] + username + '@' + domain
        print url_update_pw
        response, content = http.request(url_update_pw,'POST',headers=headers,body=userparams)
        msg = parse_qsl(response['content-location'])[0][1]
        #response, content = http.request('https://mail.ming.vn/API/logout','GET')
        print response
        web.header('Content-Type', 'application/json')
        #return json.dumps(msg)
        return json.dumps({'return_code':msg})


class CreateUser(object):
    def POST(self):
        data = web.data()
        print data
        decoded_data = parse_qs(data)
        pprint(decoded_data)
        if validate_data(decoded_data['domain'][0], decoded_data['username'][0], decoded_data['token'][0]):
            print "Create user:", decoded_data['username'][0], "with password is:", decoded_data['password'][0]
            #return create_ldap_user(decoded_data['domain'][0], decoded_data['username'][0], decoded_data['password'][0])
            input_data = {'domainName': decoded_data['domain'][0],\
                          'username': decoded_data['username'][0],\
                          'newpw': decoded_data['password'][0],\
                          'confirmpw': decoded_data['password'][0]}
            result = usertools.add(input_data)
            if not result[0]:
                return json.dumps({'return_code': result[1]})
            else:
                return json.dumps({'return_code': 'CREATED_SUCCESS'})
        else:
            print "Wrong token key!"
            msg = "INVALID_TOKEN"
            return json.dumps({'return_code':msg})
        
class UpdatePassword(object):
    def POST(self):
        data = web.data()
        print data
        decoded_data = parse_qs(data)
        pprint(decoded_data)
        if validate_data(decoded_data['domain'][0], decoded_data['username'][0], decoded_data['token'][0]):
            print "Update user:", decoded_data['username'][0], "NEW password is:", decoded_data['password'][0]
            return update_ldap_user(decoded_data['domain'][0], decoded_data['username'][0], decoded_data['password'][0])
        else:
            print "Wrong token key!"
            msg = "INVALID_TOKEN"
            return json.dumps({'return_code':msg})

## New style coding from here, will update above APIs later! ##       
import sys
sys.path.insert(0, '/usr/share/apache2/iredadmin/API')

from libs.iredbase import *  
from libs.ldaplib import connUtils, core, ldaputils
import ldap

from libs.iredutils import reEmail, reDomain
reToken = '[a-z0-9]{32}'


connutils = connUtils.Utils() 
class EmailisExisted(object):
    def POST(self):
        data = web.data()
        print data
        decoded_data = parse_qs(data)
        pprint(decoded_data)
        """ like this:
        {'domain': ['ming.vn'],
         'token': ['10dd412c5b3aca1e77954***'],
         'username': ['cuoilennghe']}
        """
        if validate_data(decoded_data['domain'][0], decoded_data['username'][0], decoded_data['token'][0]):
            req_domain = decoded_data['domain'][0]
            req_email = decoded_data['username'][0]+'@'+decoded_data['domain'][0]
            if connutils.isAccountExists(domain=req_domain, filter='(mail=%s)' % req_email):
                msg = "ALREADY_EXISTS"
            else:
                msg = "AVAILABLE"
        else:
            print "Wrong token key!"
            msg = "INVALID_TOKEN"

        print "Check availability of user: ", decoded_data['username'][0], " ---> ", msg
        web.header('Content-Type', 'application/json')
        return json.dumps({'return_code':msg})


import re
conn_pool_maildir = []
conn_pool_countmail = []
headers_on_PUT = { 'X-Kt-Mode' : 'set' }
headers_EXPIRE = { 'X-Kt-Mode' : 'set', 'X-Kt-Xt': None}
EXPIRE_TIME = 180 # seconds
pickle_proto = 2

class CountMail(object):
    def GET(self, *args):
        global MingVN_LDAP
        domain = str(args[0])
        username = str(args[1])
        #print "domain = ", domain, "username = ", username
        #print "Query = ", web.ctx.query
        try:
            decoded_data = parse_qs(web.ctx.query[1:])
            #print 'decoded_data = ', decoded_data
            token = str(decoded_data['token'][0])
            #print 'Token = ', token
            if re.search(reToken, decoded_data['token'][0]) and validate_data(domain, username, token):
                email = '%s@%s' % (username, domain)
                try:
                    kyotoconn1 = conn_pool_maildir.pop()
                except:
                    kyotoconn1 = httplib.HTTPConnection(KYOTO_HOST_MAILDIR,port=KYOTO_PORT_MAILDIR)

                try:
                    kyotoconn1.connect()
                    kyotoconn1.request('GET', email)
                    resp = kyotoconn1.getresponse()
                    body = resp.read()
                    maildir = pickle.loads(body)
                except:
                    maildir = ''
                finally:
                    conn_pool_maildir.append(kyotoconn1) ## Recycle a Kyoto connection

                if not maildir:
                    try:
                        result = MingVn_LDAP.conn.search_s('mail=%s@%s,ou=Users,domainName=%s,o=domains,dc=ming,dc=vn' % (username, domain, domain),ldap.SCOPE_BASE,'(&(objectClass=mailUser)(mail=%s@%s))' % (username, domain), ['homeDirectory'])
                        print result
                        print "-----------------------------------------------------------------------------"
                        maildir = result[0][1]['homeDirectory'][0]+"Maildir/"
                        #kyotodb.set(email, maildir)
                        body = pickle.dumps(maildir, pickle_proto)
                        try:
                            kyotoconn1 = conn_pool_maildir.pop()
                        except:
                            kyotoconn1 = httplib.HTTPConnection(KYOTO_HOST_MAILDIR,port=KYOTO_PORT_MAILDIR)

                        try:
                            kyotoconn1.connect()
                            kyotoconn1.request('PUT',email, body=body, headers=headers_on_PUT)
                        except Exception as e:
                            print "Exception: ", e
                        finally:
                            conn_pool_maildir.append(kyotoconn1) ## Recycle a Kyoto connection
                            
                    except Exception, e:
                        print ldaputils.getExceptionDesc(e)
                        msg = "USER_NOT_EXISTED"
                        web.header('Content-Type', 'application/json')
                        return json.dumps({'return_code':msg})

                ## Start count mails
                try:
                    kyotoconn2 = conn_pool_countmail.pop()
                except:
                    kyotoconn2 = httplib.HTTPConnection(KYOTO_HOST_COUNTMAIL,port=KYOTO_PORT_COUNTMAIL)
                
                try:
                    kyotoconn2.connect()        
                    kyotoconn2.request('GET', email)
                    resp = kyotoconn2.getresponse()
                    body = resp.read()
                    mailstats = pickle.loads(body)
                    #print mailstats
                except Exception as e:
                    mailstats = {}
                finally:
                    conn_pool_countmail.append(kyotoconn2) ## Recycle a Kyoto connection

                if not mailstats:
                    unread_mail, total_mail = count_mails(maildir)     #Before Greenlet-ize
                    mailstats['unread'] = unread_mail
                    mailstats['total'] = total_mail
                    #print mailstats
                    try:
                        kyotoconn2 = conn_pool_countmail.pop()
                    except:
                        kyotoconn2 = httplib.HTTPConnection(KYOTO_HOST_COUNTMAIL,port=KYOTO_PORT_COUNTMAIL)

                    try:
                        body = pickle.dumps(mailstats, pickle_proto)
                        epoch = int(time.time()) + EXPIRE_TIME;
                        headers_EXPIRE['X-Kt-Xt'] = str(epoch)

                        kyotoconn2.connect() 
                        kyotoconn2.request('PUT',email, body=body, headers=headers_EXPIRE)
                    except Exception as e:
                        print "Exception: ", e
                    finally:
                        conn_pool_countmail.append(kyotoconn2) ## Recycle a Kyoto connection

                #print "Checked %s : unread=%d, total=%d" % (maildir, unread_mail, total_mail)
                msg = "COUNTED"
                mailstats.update({'return_code':msg})
                web.header('Content-Type', 'application/json')
                return json.dumps(mailstats)
            else:
                msg = "INVALID_TOKEN"
                web.header('Content-Type', 'application/json')
                return json.dumps({'return_code':msg})
        except KeyError:
            print "EMPTY Token or MALFORMED Argument!"
            msg = "MALFORMED_ARGUMENT"
            web.header('Content-Type', 'application/json')
            return json.dumps({'return_code':msg})                    

        return "Websevice does not operate properly. Pls report for MailAdmin. Thank you!"

def count_mails(maildir):
    from os import listdir
    in_new = listdir(maildir+"new/")
    in_cur = listdir(maildir+"cur/")
    unread = 0
    total = 0

    unread += len(in_new)
    for item in in_cur:
        if item[-1:] != 'S':
            unread += 1
    total = len(in_new) + len(in_cur)
    return (unread, total)

urls = ('/create/', 'CreateUser')
urls += ('/update/', 'UpdatePassword')
urls += ('/check_avail/', 'EmailisExisted')
urls += ('/mail_stats/(%s)/(.*)/' % (reDomain), 'CountMail')


MingVn_LDAP = core.LDAPWrap()

# web.py + FAPWS3 server ==> need to run over_fapws3.py to glue it
application = web.application(urls, globals(), True).wsgifunc()

if __name__ == "__main__":
    """ 
    # web.py native
    app = web.application(urls, globals())
    app.run()
    """
    try:
        run_on_port = int(sys.argv[1])
    except:
        run_on_port = 8081

    print 'Serving on %d...' % run_on_port
    WSGIServer(('', run_on_port), application).serve_forever()
    
    """
    # web.py + Gevent server
    application = web.application(urls, globals()).wsgifunc()
    print 'Serving on 8082...'
    WSGIServer(('', 8082), application).serve_forever()
    """
   

    """ When test on shell:
    ldapsearch -LLL -S homeDirectory  -D "mail=minhcd@ming.vn,ou=Users,domainName=ming.vn,o=domains,dc=ming,dc=vn" -b "mail=minhcd@ming.vn,ou=Users,domainName=ming.vn,o=domains,dc=ming,dc=vn" -W

    ldapsearch -LLL -S homeDirectory  -D "cn=vmailadmin,dc=ming,dc=vn" -b "mail=hangpro3@ming.vn,ou=Users,domainName=ming.vn,o=domains,dc=ming,dc=vn" -w BINDING_PASSWORD_HERE
    """
