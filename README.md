# ADWSSearch & LDAP Keşif Rehberi 


---------------------------------------------------------
[TEMEL PARAMETRELER]
---------------------------------------------------------
--dn : "DC=montana,DC=local" (Zorunlu)
-a   : Getirilecek öznitelikler (name, description, sAMAccountName vb.)
--dc : Belirli bir Domain Controller hedeflemek için.

---------------------------------------------------------
[ 1. GENEL KEŞİF VE SİSTEM TESPİTİ ]
---------------------------------------------------------
# Tüm Bilgisayarları Listele (İşletim sistemiyle birlikte)
adwssearch "(objectCategory=computer)" -a name,operatingSystem,dNSHostName --dn "DC=montana,DC=local"

# Domain Controller (DC) Makinelerini Tespit Et
adwssearch "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -a name,dNSHostName --dn "DC=montana,DC=local"

# SQL Server Çalıştıran Kritik Makineleri Bul
adwssearch "(&(objectCategory=computer)(servicePrincipalName=MSSQLSvc/*))" -a name,operatingSystem --dn "DC=montana,DC=local"

---------------------------------------------------------
[ 2. KULLANICI VE YETKİ ANALİZİ ]
---------------------------------------------------------
# Domain Admin Grubuna Üye Kullanıcılar
adwssearch "(memberOf=CN=Domain Admins,CN=Users,DC=montana,DC=local)" -a sAMAccountName --dn "DC=montana,DC=local"

# Enterprise Admins (Tüm Ormanda Yetkililer)
adwssearch "(memberOf=CN=Enterprise Admins,CN=Users,DC=montana,DC=local)" -a sAMAccountName --dn "DC=montana,DC=local"

# Açıklama Satırında "pass" Geçen Hesaplar (Şifre Avı)
adwssearch "(&(objectCategory=user)(description=*pass*))" -a sAMAccountName,description --dn "DC=montana,DC=local"

---------------------------------------------------------
[ 3. İLERİ SEVİYE SALDIRI YOLLARI (ATTACK PATHS) ]
---------------------------------------------------------
# Kerberoasting (SPN Kaydı Olan Servis Hesapları)
adwssearch "(&(objectCategory=user)(servicePrincipalName=*))" -a sAMAccountName,servicePrincipalName --dn "DC=montana,DC=local"

# AS-REP Roasting (Şifresi Kolay Kırılabilenler - Pre-Auth Disabled)
adwssearch "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" -a sAMAccountName --dn "DC=montana,DC=local"

# Unconstrained Delegation (Bilet Çalınabilecek Makineler)
adwssearch "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" -a name --dn "DC=montana,DC=local"

---------------------------------------------------------
[ 4. GPO VE GÜVEN İLİŞKİLERİ ]
---------------------------------------------------------
# Domain Trust'ları (Başka Domainlere Zıplama Kapısı)
adwssearch "(objectClass=trustedDomain)" -a name,trustDirection --dn "DC=montana,DC=local"

# Mevcut GPO Listesi ve Dosya Yolları
adwssearch "(objectCategory=groupPolicyContainer)" -a displayName,gPCFileSysPath --dn "DC=montana,DC=local"

---------------------------------------------------------
[ 5. OPSEC & ZAMAN ANALİZİ ]
---------------------------------------------------------
# Son 30 Gündür Şifre Değiştirmemiş "Admin" Grupları
adwssearch "(&(objectCategory=group)(whenChanged>=20260201000000.0Z))" -a name,whenChanged --dn "DC=montana,DC=local"
