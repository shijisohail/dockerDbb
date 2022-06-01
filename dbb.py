import subprocess, re
from flask import Flask, request
from flask import jsonify
import netifaces as ni
from flask_cors import CORS, cross_origin
from flask_restful import Resource, Api
import pymongo
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from pymongo import MongoClient
from datetime import timedelta
from flask import Flask, request, jsonify, session
# Making a Connection with MongoClient
cyberange = MongoClient("mongodb://localhost:27017/")
# database
db = cyberange["cyberange"]
# collection
user = db["User"]

app = Flask(__name__)
app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(minutes=1)
CORS(app)
api = Api(app)
jwt = JWTManager(app)

# JWT Config
app.config["JWT_SECRET_KEY"] = "this-is-secret-key"


@app.route("/dashboard")
@jwt_required
def dasboard():
    return jsonify(message="Welcome! to the Data Science Learner")


@app.route("/register", methods=["POST"])
def register():
    email = request.form["email"]
    # test = User.query.filter_by(email=email).first()
    test = user.find_one({"email": email})
    if test:
        return jsonify(message="User Already Exist"), 409
    else:
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        password = request.form["password"]
        user_info = dict(first_name=first_name, last_name=last_name, email=email, password=password)
        user.insert_one(user_info)
        return jsonify(message="User added sucessfully"), 201


@app.route("/login", methods=["GET","POST"])
def login():
    #print(request.get_json())
    if  request.get_json():
    
        username = request.json["0"]
        password = request.json["1"]
        test = list(user.find({'email': username}))
        print(test[0]['password'])
        if password == test[0]['password']:
            return jsonify(message="Login Succeeded!"), 201
    else:
        user != request.form["0"]
        password != request.form["1"]
        return jsonify(message="Login Not Succeeded!"), 500

    # test = user.find_one({"0": user, "1": password})
    # if test:
    #     access_token = create_access_token(identity=user)
    # return jsonify(message="Login Succeeded!"), 201
    
 
    # else:
    #     return jsonify(message="Bad Email or Password"), 401
    #return {'test':'test'}


@app.route('/DVWA')
def dvwa_machine():
    machine1 = 'santosomar/dvwa'
    subprocess.run(['sudo', 'docker', 'run', '--rm', '-d', '-p', ':80', machine1]) 
    op = bytes.decode(subprocess.check_output('sudo docker ps --latest', shell=True))
    word = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:(\d+)")
    port = re.findall(word, op)
    ni.ifaddresses('eno4')
    ip = ni.ifaddresses('eno4')[ni.AF_INET][0]['addr']

    print(port)
    print(ip)
    return jsonify(ip + ':' + str(port[0]))
    

@app.route('/Mutil')
def mutlil():
    machine2 = 'szsecurity/mutillidae'
    subprocess.run(['sudo', 'docker', 'run', '--rm', '-d', '-p', ':80', machine2])
    op = bytes.decode(subprocess.check_output('sudo docker ps --latest', shell=True))
    word = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:(\d+)")
    port = re.findall(word, op)
    ni.ifaddresses('eno4')
    ip = ni.ifaddresses('eno4')[ni.AF_INET][0]['addr']

    print(port)
    print(ip)
    return jsonify(ip + ':' + str(port[0]))

@app.route('/BWAPP')
def BWAPP_machine():
    #machine3 = 'raesene/bwapp'
    machine3 = 'feltsecure/owasp-bwapp'
    subprocess.run(['sudo', 'docker', 'run', '--rm', '-d', '-p', ':80', machine3])
    op = bytes.decode(subprocess.check_output('sudo docker ps --latest', shell=True))
    word = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:(\d+)")
    port = re.findall(word, op)
    ni.ifaddresses('eno4')
    ip = ni.ifaddresses('eno4')[ni.AF_INET][0]['addr']

    print(port)
    print(ip)
    return jsonify(ip + ':' + str(port[0]))

@app.route('/JUICE_SHOP')
def Juice_machine():
    machine4 = 'bkimminich/juice-shop'
    subprocess.run(['sudo', 'docker', 'run', '--rm', '-d', '-p', ':80', machine4])
    op = bytes.decode(subprocess.check_output('sudo docker ps --latest', shell=True))
    word = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:(\d+)")
    port = re.findall(word, op)
    ni.ifaddresses('eno4')
    ip = ni.ifaddresses('eno4')[ni.AF_INET][0]['addr']

    print(port)
    print(ip)
    return jsonify(ip + ':' + str(port[0]))    

@app.route('/badstore')
def badstore():
    machine5 = 'jvhoof/badstore-docker'
    subprocess.run(['sudo', 'docker', 'run', '--rm', '-d', '-p', ':80', machine5])
    op = bytes.decode(subprocess.check_output('sudo docker ps --latest', shell=True))
    word = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:(\d+)")
    port = re.findall(word, op)
    ni.ifaddresses('eno4')
    ip = ni.ifaddresses('eno4')[ni.AF_INET][0]['addr']

    print(port)
    print(ip)
    return jsonify(ip + ':' + str(port[0]))  

@app.route('/gruyere')
def gruyere():
    machine6= 'karthequian/gruyere'
    subprocess.run(['sudo', 'docker', 'run', '--rm', '-d', '-p', ':80', machine6])
    op = bytes.decode(subprocess.check_output('sudo docker ps --latest', shell=True))
    word = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:(\d+)")
    port = re.findall(word, op)
    ni.ifaddresses('eno4')
    ip = ni.ifaddresses('eno4')[ni.AF_INET][0]['addr']

    print(port)
    print(ip)
    return jsonify(ip + ':' + str(port[0]))  
    
    

@app.route('/hackazone')
def hackzone():
    machine7 = 'yossiros/hackazone'
    subprocess.run(['sudo', 'docker', 'run', '--rm', '-d', '-p', ':80', machine7])
    op = bytes.decode(subprocess.check_output('sudo docker ps --latest', shell=True))
    word = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:(\d+)")
    port = re.findall(word, op)
    ni.ifaddresses('eno4')
    ip = ni.ifaddresses('eno4')[ni.AF_INET][0]['addr']

    print(port)
    print(ip)
    return jsonify(ip + ':' + str(port[0]))  
    
    
    
    
@app.route('/wackopicko')
def wackopicko():
    machine8 = 'adamdoupe/wackopicko'
    subprocess.run(['sudo', 'docker', 'run', '--rm', '-d', '-p', ':80', machine8])
    op = bytes.decode(subprocess.check_output('sudo docker ps --latest', shell=True))
    word = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:(\d+)")
    port = re.findall(word, op)
    ni.ifaddresses('eno4')
    ip = ni.ifaddresses('eno4')[ni.AF_INET][0]['addr']

    print(port)
    print(ip)
    return jsonify(ip + ':' + str(port[0])) 
    
@app.route('/XVWA')
def XVWA():
    machine9 = 'tuxotron/xvwa'
    subprocess.run(['sudo', 'docker', 'run', '--rm', '-d', '-p', ':80', machine9])
    op = bytes.decode(subprocess.check_output('sudo docker ps --latest', shell=True))
    word = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:(\d+)")
    port = re.findall(word, op)
    ni.ifaddresses('eno4')
    ip = ni.ifaddresses('eno4')[ni.AF_INET][0]['addr']

    print(port)
    print(ip)
    return jsonify(ip + ':' + str(port[0])) 

@app.route('/OWASP')
def OWASP():
    machine10 = 'gjuniioor/owasp-bricks'
    subprocess.run(['sudo', 'docker', 'run', '--rm', '-d', '-p', ':80', machine10])
    op = bytes.decode(subprocess.check_output('sudo docker ps --latest', shell=True))
    word = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:(\d+)")
    port = re.findall(word, op)
    ni.ifaddresses('eno4')
    ip = ni.ifaddresses('eno4')[ni.AF_INET][0]['addr']

    print(port)
    print(ip)
    return jsonify(ip + ':' + str(port[0]))
    
########################TEST#################################

#############################################################    
    

#@app.route('/ctf')
#def ctf1():
#
#    subprocess.run(['sudo', 'docker', 'run', '--net', 'ctf', '--ip', '172.16.223.4', '-i','-t', 'ctf1', '--fixed-cidr']) 
#    return jsonify('172.16.223.4')



@app.route('/ctf1')
def ctf_machine1():

   
    process = subprocess.Popen(['sudo', 'docker', 'run', '--net', 'ctf', '--ip', '172.16.223.4', '-i','-t','-d', 'ctf1', 'bash'], 
    stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    #print(stdout)

    #return jsonify("172.16.223.4" + ':' + str(stdout))
    return jsonify("172.16.223.4")

@app.route('/ctf2')
def ctf_machine22():

   
    process = subprocess.Popen(['sudo', 'docker', 'run', '--net', 'ctf', '--ip', '172.16.223.5', '-i','-t','-d', 'ctf2', 'bash'], 
    stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    #print(stdout)

    #return jsonify("172.16.223.4" + ':' + str(stdout))
    return jsonify("172.16.223.5")

@app.route('/webctf3')
def ctf_machine33():

   
     process = subprocess.Popen(['sudo', 'docker', 'run', '--net', 'ctf', '--ip', '172.16.223.6', 'webctf3'], 
     stdout=subprocess.PIPE,stderr=subprocess.PIPE) 
     stdout, stderr = process.communicate()
     print(stdout)
     return jsonify("172.10.0.2")
    
    
    
class stopMachine(Resource):
	@app.route('/stopMachine', methods=['POST', 'GET'])
	def stop():
            port = request.get_json()
            port = str(port[0])
            print(port)
            print(type(port))
            try:
                for line in bytes.decode(subprocess.check_output('sudo docker ps', shell=True)).split(sep="\n"):
                    if port in line:
                        word = line.split()[0]
                        subprocess.run(['sudo', 'docker', 'stop', word])
                return 'success'
            except:
                return 'faild'



api.add_resource(stopMachine, '/stopMachine')

if __name__ == '__main__':
   app.run(host="10.97.12.165")
