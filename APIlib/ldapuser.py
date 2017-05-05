import sys
sys.path.insert(0, '/usr/share/apache2/iredadmin/API')

from libs.iredbase import *

import types
import ldap
import ldap.filter
import web
from libs import iredutils
from libs.ldaplib import core, domain as domainlib, attrs, ldaputils, iredldif, connUtils

#from libs.iredbase import *
cfg = web.iredconfig
#session = web.config.get('_session')


class User(core.LDAPWrap):
    def __del__(self):
        try:
            self.conn.unbind()
        except:
            pass
    
    """
    # Get values of user or domain catch-all account.
    # accountType in ['user', 'catchall',]
    def profile(self, domain, mail, accountType='user'):
        self.mail = web.safestr(mail)
        self.domain = self.mail.split('@', 1)[-1]

        if self.domain != domain:
            return web.seeother('/domains?msg=PERMISSION_DENIED')

        self.filter = '(&(objectClass=mailUser)(mail=%s))' % (self.mail,)
        if accountType == 'catchall':
            self.filter = '(&(objectClass=mailUser)(mail=@%s))' % (self.mail,)
        else:
            if not self.mail.endswith('@' + self.domain):
                return web.seeother('/domains?msg=PERMISSION_DENIED')

        if attrs.RDN_USER == 'mail':
            self.searchdn = ldaputils.convKeywordToDN(self.mail, accountType=accountType)
            self.scope = ldap.SCOPE_BASE
        else:
            self.searchdn = attrs.DN_BETWEEN_USER_AND_DOMAIN + ldaputils.convKeywordToDN(self.domain, accountType='domain')
            self.scope = ldap.SCOPE_SUBTREE

        try:
            self.user_profile = self.conn.search_s(
                self.searchdn,
                self.scope,
                self.filter,
                attrs.USER_ATTRS_ALL,
            )
            return (True, self.user_profile)
        except Exception, e:
            return (False, ldaputils.getExceptionDesc(e))
    """

    def add(self, data):
        # Get domain name, username, cn.
        self.domain = web.safestr(data.get('domainName')).strip().lower()
        self.username = web.safestr(data.get('username')).strip().lower()
        self.mail = self.username + '@' + self.domain
        self.groups = data.get('groups', [])

        if not iredutils.isDomain(self.domain) or not iredutils.isEmail(self.mail):
            return (False, 'MISSING_DOMAIN_OR_USERNAME')

        # Check account existing.
        connutils = connUtils.Utils()
        if connutils.isAccountExists(domain=self.domain, filter='(mail=%s)' % self.mail):
            return (False, 'ALREADY_EXISTS')

        # Get @domainAccountSetting.
        domainLib = domainlib.Domain()
        result_domain_profile = domainLib.profile(self.domain)
        
        # Initial parameters.
        domainAccountSetting = {}
        self.aliasDomains = []

        if result_domain_profile[0] is True:
            domainProfile = result_domain_profile[1]
            domainAccountSetting = ldaputils.getAccountSettingFromLdapQueryResult(domainProfile, key='domainName').get(self.domain, {})
            self.aliasDomains = domainProfile[0][1].get('domainAliasName', [])

        # Check password.
        self.newpw = web.safestr(data.get('newpw'))
        self.confirmpw = web.safestr(data.get('confirmpw'))

        result = iredutils.verifyNewPasswords(self.newpw, self.confirmpw,
                                          min_passwd_length=domainAccountSetting.get('minPasswordLength', '0'),
                                          max_passwd_length=domainAccountSetting.get('maxPasswordLength', '0'),
                                         )
        if result[0] is True:
            self.passwd = ldaputils.generatePasswd(result[1])
        else:
            return result

        # Get display name.
        self.cn = data.get('cn')

        # Get user quota. Unit is MB.
        # 0 or empty is not allowed if domain quota is set, set to
        # @defaultUserQuota or @domainSpareQuotaSize

        # Initial final mailbox quota.
        self.quota = 0

        # Get mail quota from web form.
        defaultUserQuota = domainLib.getDomainDefaultUserQuota(self.domain, domainAccountSetting)
        self.mailQuota = str(data.get('mailQuota')).strip()
        if self.mailQuota.isdigit():
            self.mailQuota = int(self.mailQuota)
        else:
            self.mailQuota = defaultUserQuota

        # 0 means unlimited.
        domainQuotaSize, domainQuotaUnit = domainAccountSetting.get('domainQuota', '0:GB').split(':')
        if int(domainQuotaSize) == 0:
            # Unlimited.
            self.quota = self.mailQuota
        else:
            # Get domain quota, convert to MB.
            if domainQuotaUnit == 'TB':
                domainQuota = int(domainQuotaSize) * 1024 * 1024 # TB
            elif domainQuotaUnit == 'GB':
                domainQuota = int(domainQuotaSize) * 1024  # GB
            else:
                domainQuota = int(domainQuotaSize)  # MB

            # TODO Query whole domain and calculate current quota size, not read from domain profile.
            #domainCurrentQuotaSize = int(domainProfile[0][1].get('domainCurrentQuotaSize', ['0'])[0]) / (1024*1024)
            result = connutils.getDomainCurrentQuotaSizeFromLDAP(domain=self.domain)
            if result[0] is True:
                domainCurrentQuotaSize = result[1]
            else:
                domainCurrentQuotaSize = 0

            # Spare quota.
            domainSpareQuotaSize = domainQuota - domainCurrentQuotaSize/(1024*1024)

            if domainSpareQuotaSize <= 0:
                return (False, 'EXCEEDED_DOMAIN_QUOTA_SIZE')

            # Get FINAL mailbox quota.
            if self.mailQuota == 0:
                self.quota = domainSpareQuotaSize
            else:
                if domainSpareQuotaSize > self.mailQuota:
                    self.quota = self.mailQuota
                else:
                    self.quota = domainSpareQuotaSize

        # Get default groups.
        self.groups = [ web.safestr(v)
                       for v in domainAccountSetting.get('defaultList', '').split(',')
                       if iredutils.isEmail(v)
                      ]

        self.defaultStorageBaseDirectory = domainAccountSetting.get('defaultStorageBaseDirectory', None)

        # Get default mail list which set in domain accountSetting.
        ldif = iredldif.ldif_mailuser(
            domain=self.domain,
            aliasDomains=self.aliasDomains,
            username=self.username,
            cn=self.cn,
            passwd=self.passwd,
            quota=self.quota,
            groups=self.groups,
            storageBaseDirectory=self.defaultStorageBaseDirectory,
        )

        if attrs.RDN_USER == 'mail':
            self.dn = ldaputils.convKeywordToDN(self.mail, accountType='user')
        elif attrs.RDN_USER == 'cn':
            self.dn = 'cn=' + self.cn + ',' + attrs.DN_BETWEEN_USER_AND_DOMAIN + \
                    ldaputils.convKeywordToDN(self.domain, accountType='domain')
        elif attrs.RDN_USER == 'uid':
            self.dn = 'uid=' + self.username + ',' + attrs.DN_BETWEEN_USER_AND_DOMAIN + \
                    ldaputils.convKeywordToDN(self.domain, accountType='domain')
        else:
            return (False, 'UNSUPPORTED_USER_RDN')

        try:
            self.conn.add_s(ldap.filter.escape_filter_chars(self.dn), ldif,)
            web.logger(msg="Create user: %s." % (self.mail), domain=self.domain, event='create',)
            return (True,)
        except ldap.ALREADY_EXISTS:
            return (False, 'ALREADY_EXISTS')
        except Exception, e:
            return (False, ldaputils.getExceptionDesc(e))

    """
    def delete(self, domain, mails=[]):
        if mails is None or len(mails) == 0:
            return (False, 'NO_ACCOUNT_SELECTED')

        self.domain = web.safestr(domain)
        self.mails = [str(v) for v in mails if iredutils.isEmail(v) and str(v).endswith('@'+self.domain)]

        self.domaindn = ldaputils.convKeywordToDN(self.domain, accountType='domain')

        if not iredutils.isDomain(self.domain):
            return (False, 'INVALID_DOMAIN_NAME')

        result = {}
        for mail in self.mails:
            self.mail = web.safestr(mail)

            try:
                # Delete user object (ldap.SCOPE_BASE).
                self.deleteSingleUser(self.mail,)
                

                # Delete user object and whole sub-tree.
                # Get dn of mail user and domain.
                #""
                self.userdn = ldaputils.convKeywordToDN(self.mail, accountType='user')
                deltree.DelTree(self.conn, self.userdn, ldap.SCOPE_SUBTREE)

                # Log delete action.
                web.logger(
                    msg="Delete user: %s." % (self.mail),
                    domain=self.mail.split('@')[1],
                    event='delete',
                )
                #""

            except ldap.LDAPError, e:
                result[self.mail] = ldaputils.getExceptionDesc(e)

        if result == {}:
            return (True,)
        else:
            return (False, str(result))

    def enableOrDisableAccount(self, domain, mails, action, attr='accountStatus',):
        if mails is None or len(mails) == 0:
            return (False, 'NO_ACCOUNT_SELECTED')

        self.mails = [str(v)
                      for v in mails
                      if iredutils.isEmail(v)
                      and str(v).endswith('@'+str(domain))
                     ]

        result = {}
        connutils = connUtils.Utils()
        for mail in self.mails:
            self.mail = web.safestr(mail)
            if not iredutils.isEmail(self.mail):
                continue

            self.domain = self.mail.split('@')[-1]
            self.dn = ldaputils.convKeywordToDN(self.mail, accountType='user')

            try:
                connutils.enableOrDisableAccount(
                    domain=self.domain,
                    account=self.mail,
                    dn=self.dn,
                    action=web.safestr(action).strip().lower(),
                    accountTypeInLogger='user',
                )
            except ldap.LDAPError, e:
                result[self.mail] = str(e)

        if result == {}:
            return (True,)
        else:
            return (False, str(result))

    def update(self, profile_type, mail, data):
        self.profile_type = web.safestr(profile_type)
        self.mail = str(mail).lower()
        self.domain = self.mail.split('@', 1)[-1]

        domainAccountSetting = {}

        connutils = connUtils.Utils()
        domainLib = domainlib.Domain()

        # Get account dn.
        self.dn = connutils.getDnWithKeyword(self.mail, accountType='user')

        try:
            result = domainLib.getDomainAccountSetting(domain=self.domain)
            if result[0] is True:
                domainAccountSetting = result[1]
        except Exception, e:
            pass

        mod_attrs = []
        if self.profile_type == 'general':
            # Get cn.
            cn = data.get('cn', None)
            mod_attrs += ldaputils.getSingleModAttr(attr='cn', value=cn, default=self.mail.split('@')[0])

            # Update employeeNumber, mobile, title.
            for tmp_attr in ['employeeNumber', 'mobile', 'title',]:
                mod_attrs += ldaputils.getSingleModAttr(attr=tmp_attr, value=data.get(tmp_attr), default=None)

            ############
            # Get quota

            # Get mail quota from web form.
            quota = web.safestr(data.get('mailQuota', '')).strip()
            oldquota = web.safestr(data.get('oldMailQuota', '')).strip()
            if not oldquota.isdigit():
                oldquota = 0
            else:
                oldquota = int(oldquota)

            if quota == '' or not quota.isdigit():
                # Don't touch it, keep original value.
                pass
            else:
                #mod_attrs += [( ldap.MOD_REPLACE, 'mailQuota', str(int(mailQuota) * 1024 * 1024) )]
                # Assign quota which got from web form.
                mailQuota = int(quota)

                # If mailQuota > domainSpareQuotaSize, use domainSpareQuotaSize.
                # if mailQuota < domainSpareQuotaSize, use mailQuota
                # 0 means unlimited.
                domainQuotaSize, domainQuotaUnit = domainAccountSetting.get('domainQuota', '0:GB').split(':')

                if int(domainQuotaSize) == 0:
                    # Unlimited. Keep quota which got from web form.
                    mod_attrs += [(ldap.MOD_REPLACE, 'mailQuota', str(mailQuota*1024*1024))]
                else:
                    # Get domain quota.
                    if domainQuotaUnit == 'TB':
                        domainQuota = int(domainQuotaSize) * 1024 * 1024 # TB
                    elif domainQuotaUnit == 'GB':
                        domainQuota = int(domainQuotaSize) * 1024  # GB
                    else:
                        domainQuota = int(domainQuotaSize)  # MB

                    # Query LDAP and get current domain quota size.
                    result = connutils.getDomainCurrentQuotaSizeFromLDAP(domain=self.domain)
                    if result[0] is True:
                        domainCurrentQuotaSizeInBytes = result[1]
                    else:
                        domainCurrentQuotaSizeInBytes = 0

                    # Spare quota.
                    domainSpareQuotaSize = (domainQuota + oldquota) - (domainCurrentQuotaSizeInBytes/(1024*1024))

                    if domainSpareQuotaSize <= 0:
                        # Don't update quota if already exceed domain quota size.
                        #return (False, 'EXCEEDED_DOMAIN_QUOTA_SIZE')

                        # Set to 1MB. don't exceed domain quota size.
                        mod_attrs += [(ldap.MOD_REPLACE, 'mailQuota', str(1024*1024))]
                    else:
                        # Get FINAL mailbox quota.
                        if mailQuota >= domainSpareQuotaSize:
                            mailQuota = domainSpareQuotaSize
                        mod_attrs += [(ldap.MOD_REPLACE, 'mailQuota', str(mailQuota*1024*1024))]
            # End quota
            ############

            # Get telephoneNumber.
            telephoneNumber = data.get('telephoneNumber', [])
            nums = [str(num) for num in telephoneNumber if len(num) > 0]
            mod_attrs += [(ldap.MOD_REPLACE, 'telephoneNumber', nums)]

            # Get accountStatus.
            if 'accountStatus' in data.keys():
                accountStatus = 'active'
            else:
                accountStatus = 'disabled'
            mod_attrs += [ (ldap.MOD_REPLACE, 'accountStatus', accountStatus) ]

        elif self.profile_type == 'password':
            # Get password length from @domainAccountSetting.
            minPasswordLength = domainAccountSetting.get('minPasswordLength', cfg.general.get('min_passwd_length', '0'))
            maxPasswordLength = domainAccountSetting.get('maxPasswordLength', cfg.general.get('max_passwd_length', '0'))

            # Get new passwords from user input.
            self.newpw = str(data.get('newpw', None))
            self.confirmpw = str(data.get('confirmpw', None))

            result = iredutils.verifyNewPasswords(
                newpw=self.newpw,
                confirmpw=self.confirmpw,
                min_passwd_length=minPasswordLength,
                max_passwd_length=maxPasswordLength,
            )
            if result[0] is True:
                self.passwd = ldaputils.generatePasswd(result[1])
                mod_attrs += [ (ldap.MOD_REPLACE, 'userPassword', self.passwd) ]
            else:
                return result

        try:
            self.conn.modify_s(self.dn, mod_attrs)
            return (True,)
        except Exception, e:
            return (False, ldaputils.getExceptionDesc(e))

            """
