"""
XSA Python buildpack app example
Author: Andrew Lunde 
"""
import sys
print(sys.path)
from flask import Flask
from flask import request
from flask import Response
from flask import send_from_directory
#   
import os
#import pyhdb
# Downloading pyhdb-0.3.3.tar.gz
import json
import datetime
#import Crypto.PublicKey.RSA as RSA
#import jws.utils
#import python_jwt as jwt
#https://help.sap.com/viewer/4505d0bdaf4948449b7f7379d24d0f0d/2.0.03/en-US/8732609bd5314b51a17d6a3cc09110c3.html#loio8732609bd5314b51a17d6a3cc09110c3__section_atx_2vt_vt
from sap import xssec
from cfenv import AppEnv
#
#from sap.cf_logging import flask_logging
#
#https://help.sap.com/viewer/0eec0d68141541d1b07893a39944924e/2.0.03/en-US/d12c86af7cb442d1b9f8520e2aba7758.html
from hdbcli import dbapi

import hana_ml

#https://help.sap.com/doc/1d0ebfe5e8dd44d09606814d83308d4b/2.0.05/en-US/index.html
from hana_ml import dataframe
from hana_ml.algorithms.apl import classification

import time

app = Flask(__name__)
env = AppEnv()

# Get port from environment variable or choose 9099 as local default
# If you are testing locally (i.e. not with xs or cf deployments,
# Be sure to pull all the python modules locally 
#   with pip using XS_PYTHON unzipped to /tmp
# mkdir -p local
# pip install -t local -r requirements.txt -f /tmp
port = int(os.getenv("PORT", 9099))
hana = env.get_service(label='hana')

def attach(port, host):
    try:
        import pydevd
        pydevd.stoptrace() #I.e.: disconnect if already connected
        # pydevd.DebugInfoHolder.DEBUG_RECORD_SOCKET_READS = True
        # pydevd.DebugInfoHolder.DEBUG_TRACE_BREAKPOINTS = 3
        # pydevd.DebugInfoHolder.DEBUG_TRACE_LEVEL = 3
        pydevd.settrace(
            port=port,
            host=host,
            stdoutToServer=True,
            stderrToServer=True,
            overwrite_prev_trace=True,
            suspend=False,
            trace_only_current_thread=False,
            patch_multiprocessing=False,
        )
    except:
        import traceback;traceback.print_exc() 
        
# This module's Flask webserver will respond to these three routes (URL paths)
# If there is no path then just return Hello World and this module's instance number
# Requests passed through the app-router will never hit this route.
@app.route('/')
def hello_world():
    output = '<strong>Hallo World! I am instance ' + str(os.getenv("CF_INSTANCE_INDEX", 0)) + '</strong> Try these links.</br>\n'
    output += '<a href="/python/test">/python/test</a><br />\n'
    output += '<a href="/python/env">/python/env</a><br />\n'
    output += '<a href="/python/db_only">/python/db_only</a><br />\n'
    output += '<a href="/auth_python/db_valid">/auth_python/db_valid</a><br />\n'
    return output
    
# Satisfy browser requests for favicon.ico so that don't return 404
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/python/env')
def dump_env():
    output = '\n Key Environment variables... \n'
    output += 'PYTHONHOME: ' + str(os.getenv("PYTHONHOME", 0)) + '\n'
    output += 'PYTHONPATH: ' + str(os.getenv("PYTHONPATH", 0)) + '\n'
    output += 'VCAP_SERVICES: ' + str(os.getenv("VCAP_SERVICES", 0)) + '\n'
    output += 'host: ' + hana.credentials['host'] + '\n'
    output += 'port: ' + hana.credentials['port'] + '\n'
    output += 'user: ' + hana.credentials['user'] + '\n'
    output += 'pass: ' + hana.credentials['password'] + '\n'
    if 'certificate' in hana.credentials:
        output += 'cert: ' + hana.credentials['certificate'] + '\n'
    output += '\n'
    return output

# Coming through the app-router
@app.route('/python/links')
def python_links():
    output = '<strong>Hello World! I am instance ' + str(os.getenv("CF_INSTANCE_INDEX", 0)) + '</strong> Try these links.</br>\n'
    output += '<a href="/python/test">/python/test</a><br />\n'
    output += '<a href="/python/env">/python/env</a><br />\n'
    output += '<a href="/python/db_only">/python/db_only</a><br />\n'
    output += '<a href="/auth_python/db_valid">/auth_python/db_valid</a><br />\n'
    return output

# If there is a request for a python/test, return Testing message and module's instance number
@app.route('/python/test')
def unauth_test():
    return 'Python UnAuthorized Test, Yo! <br />\nI am instance ' + str(os.getenv("CF_INSTANCE_INDEX", 0))

# If there is a request for a python/test2, return Testing message and then check JWT and connect to the data service and retrieve some data
@app.route('/python/db_only')
def unauth_db_only():
    output = 'Python UnAuthorized DB Only. \n'
    output += '\n'
    output += 'Receiving module should check that it came from our approuter and verify or abort if otherwise.\n'
    output += '\n'
    svcs_json = str(os.getenv("VCAP_SERVICES", 0))
    svcs = json.loads(svcs_json)

    schema = hana.credentials['schema']
    host = hana.credentials['host']
    port = hana.credentials['port']
    user = hana.credentials['user']
    password = hana.credentials['password']

    # The certificate will available for HANA service instances that require an encrypted connection
    # Note: This was tested to work with python hdbcli-2.3.112 tar.gz package not hdbcli-2.3.14 provided in XS_PYTHON00_0-70003433.ZIP  
    if 'certificate' in hana.credentials:
        haascert = hana.credentials['certificate']
    
    output += 'schema: ' + schema + '\n'
    output += 'host: ' + host + '\n'
    output += 'port: ' + port + '\n'
    output += 'user: ' + user + '\n'
    output += 'pass: ' + password + '\n'

#    # Connect to the python HANA DB driver using the connection info
# User for HANA as a Service instances
    if 'certificate' in hana.credentials:
        connection = dbapi.connect(
            address=host,
            port=int(port),
            user=user,
            password=password,
            currentSchema=schema,
            encrypt="true",
            sslValidateCertificate="true",
            sslCryptoProvider="openssl",
            sslTrustStore=haascert
        )
    else:
        connection = dbapi.connect(host,int(port),user,password)

#    # Prep a cursor for SQL execution
    cursor = connection.cursor()

#    # Form an SQL statement to retrieve some data
    if 'certificate' in hana.credentials:
        cursor.execute('SELECT "ID","ATTRIBUTE1","ATTRIBUTE2","ATTRIBUTE3","ATTRIBUTE4","LABEL" FROM "' + '' + '"."mta_python_ml.db.data::mnist.extrain"')
    else:
        cursor.execute('SELECT "ID","ATTRIBUTE1","ATTRIBUTE2","ATTRIBUTE3","ATTRIBUTE4","LABEL" FROM "' + schema + '"."mta_python_ml.db.data::mnist.extrain"')

#    # Execute the SQL and capture the result set
    extrain_vals = cursor.fetchall()
#
#    # Loop through the result set and output
    for extrain_val in extrain_vals:
        output += 'extrain[' + str(extrain_val[0]) + ']'
        output += ' at1: ' + str(extrain_val[1])
        output += ' at2: ' + str(extrain_val[2])
        output += ' at3: ' + str(extrain_val[3])
        output += ' at4: ' + str(extrain_val[4])
        output += ' lab: ' + str(extrain_val[5]) + '\n'
#
#    # Close the DB connection
    connection.close()
#
    # Return the results
    # return output
    return Response(output, mimetype='text/plain')

@app.route('/python/post', methods=['POST'])
def unauth_post():
    output = 'Python Post to DB (Dangerous!). \n'
    output += '\n'
    output += 'Receiving module should check that it came from our approuter and verify or abort if otherwise.\n'
    output += '\n'

    content = request.json

    if True:
        svcs_json = str(os.getenv("VCAP_SERVICES", 0))
        svcs = json.loads(svcs_json)

        schema = hana.credentials['schema']
        host = hana.credentials['host']
        port = hana.credentials['port']
        user = hana.credentials['user']
        password = hana.credentials['password']

        # The certificate will available for HANA service instances that require an encrypted connection
        # Note: This was tested to work with python hdbcli-2.3.112 tar.gz package not hdbcli-2.3.14 provided in XS_PYTHON00_0-70003433.ZIP  
        if 'certificate' in hana.credentials:
            haascert = hana.credentials['certificate']
            if haascert is None:
                del hana.credentials['certificate']

        output += 'schema: ' + schema + '\n'
        output += 'host: ' + host + '\n'
        output += 'port: ' + port + '\n'
        output += 'user: ' + user + '\n'
        output += 'pass: ' + password + '\n'

        #    # Connect to the python HANA DB driver using the connection info
        # User for HANA as a Service instances
        if 'certificate' in hana.credentials:
            connection = dbapi.connect(
                address=host,
                port=int(port),
                user=user,
                password=password,
                currentSchema=schema,
                encrypt="true",
                sslValidateCertificate="true",
                sslCryptoProvider="openssl",
                sslTrustStore=haascert
            )
        else:
            connection = dbapi.connect(host,int(port),user,password)

        #    # Prep a cursor for SQL execution
        cursor = connection.cursor()

        if 'action' in content:
            # See if it's an action to perform...

            if content["action"] == "clearTraining":

                if 'certificate' in hana.credentials:
                    exresult = cursor.execute('DELETE FROM "mta_python_ml.db.data::mnist.train"')
                else:
                    exresult = cursor.execute('DELETE FROM "' + schema + '"."mta_python_ml.db.data::mnist.train"')

                content["result"] = "Result is: " + str(exresult)
            else:
                content["result"] = "Unknown action: " + content["action"]

            response = content


        else:
            # Clear the test data table

            if 'certificate' in hana.credentials:
                cursor.execute('DELETE FROM "mta_python_ml.db.data::mnist.test"')
            else:
                cursor.execute('DELETE FROM "' + schema + '"."mta_python_ml.db.data::mnist.test"')

            # Put incoming number image data and target into the test data table.

            sql = ""

            if 'certificate' in hana.credentials:
                sql += 'INSERT INTO "mta_python_ml.db.data::mnist.test" VALUES('
            else:
                sql += 'INSERT INTO "' + schema + '"."mta_python_ml.db.data::mnist.test" VALUES('

            sql += str(content["numberTarget"]) + ","
            for idx,val in enumerate(content["numberData"]):
                if idx < (len(content["numberData"])-1):
                    sql += str(val) + ","
                else:
                    sql += str(val) + ""
            sql += ")"

            cursor.execute(sql)

            response = {
                "response": "Response Object"
            }

            # See if there is any training data

            # Fit

            from hana_ml import dataframe
            from hana_ml.algorithms import svm
            
            if 'certificate' in hana.credentials:
                connection_context = dataframe.ConnectionContext(address=host, port=int(port), user=user, password=password, currentSchema=schema, encrypt="true", sslValidateCertificate="true", sslCryptoProvider="openssl", sslTrustStore=haascert)
            else:
                connection_context = dataframe.ConnectionContext(host, int(port), user, password)

            df_fit = connection_context.table("mta_python_ml.db.data::mnist.train", schema=schema)
            num_training_images = len(df_fit)

            response["num_training_images"] = num_training_images

            if num_training_images < 10:
                response["training_secs_msg"] = "Need at least " + str(10 - num_training_images) + " more images to train."

            else:
                svc = svm.SVC(connection_context, gamma=0.005)
                start_time = time.time()
                svc.fit(df_fit,label='LABEL',has_id=True)
                training_secs_msg = ('Fitting of Training Data Time: {} seconds'.format(time.time() - start_time))

                response["training_secs_msg"] = training_secs_msg

                # Predict

                df_predict = connection_context.table("mta_python_ml.db.data::mnist.test", schema=schema).drop(['LABEL'])

                start_time = time.time()
                predicted_df = svc.predict(df_predict)
                predict_secs_msg = ('Predicting of Test Data Time: {} seconds'.format(time.time() - start_time))

                response["predict_secs_msg"] = predict_secs_msg

                pdf_predicted = predicted_df.select(['ID','SCORE']).collect()

                for index, row in pdf_predicted.iterrows():
                    predict_target = row["SCORE"]

                response["predict_target"] = predict_target

            # Put incoming number image data and target into the training data
            # table. (for next time)
            sql = ""

            if 'certificate' in hana.credentials:
                sql += 'INSERT INTO "mta_python_ml.db.data::mnist.train" VALUES('
            else:
                sql += 'INSERT INTO "' + schema + '"."mta_python_ml.db.data::mnist.train" VALUES('
            sql += str(content["numberTarget"]) + ","
            for idx,val in enumerate(content["numberData"]):
                if idx < (len(content["numberData"])-1):
                    sql += str(val) + ","
                else:
                    sql += str(val) + ""
            sql += ")"

            cursor.execute(sql)

        # Execute the SQL and capture the result set
        #ret_vals = cursor.fetchall()
        #
        # Loop through the result set and output
        #for ret_val in ret_vals:
        #    output += 'ret_val: ' + str(ret_val[1]) + '\n'
        #
        #    # Close the DB connection
        connection.close()
        #
        #output = {"sql":sql}
        #output = json.dumps({"sql":sql})
        #output = json.dumps(content)
        output = json.dumps(response)
    else:
        content = {"content":content["numberTarget"]}
        output = json.dumps(content)

    # Return the results
    # return output
    return Response(output, mimetype='application/json' , status=201,)

# If there is a request for a python/test2, return Testing message and then check JWT and connect to the data service and retrieve some data
@app.route('/auth_python/db_valid')
def auth_db_valid():
    output = 'Python Authorized DB Validated Request. \n'
    output += '\n'
    output += 'Receiving module should check that it came from our approuter and verify or abort if otherwise.\n'
    output += '\n'
    svcs_json = str(os.getenv("VCAP_SERVICES", 0))
    svcs = json.loads(svcs_json)

    uaa_service = env.get_service(label='xsuaa').credentials
    access_token = request.headers.get('authorization')[7:]

    security_context = xssec.create_security_context(access_token, uaa_service)
    isAuthorized = security_context.check_scope('openid')
    if not isAuthorized:
        abort(403)

    output += 'get_logon_name: ' + security_context.get_logon_name() + '\n'
    output += 'get_email: ' + security_context.get_email() + '\n'
    output += 'get_identity_zone: ' + security_context.get_identity_zone() + '\n'
    
#    # This module should only proced with any further execution if the JWT has been verified.
#    # In this example we blindly continue, but this is not the best practice.
#
    schema = hana.credentials['schema']
    host = hana.credentials['host']
    port = hana.credentials['port']
    user = hana.credentials['user']
    password = hana.credentials['password']

    # The certificate will available for HANA service instances that require an encrypted connection
    # Note: This was tested to work with python hdbcli-2.3.112 tar.gz package not hdbcli-2.3.14 provided in XS_PYTHON00_0-70003433.ZIP  
    if 'certificate' in hana.credentials:
        haascert = hana.credentials['certificate']

    output += 'schema: ' + schema + '\n'
    output += 'host: ' + host + '\n'
    output += 'port: ' + port + '\n'
    output += 'user: ' + user + '\n'
    output += 'pass: ' + password + '\n'

    if 'certificate' in hana.credentials:
        connection = dbapi.connect(
            address=host,
            port=int(port),
            user=user,
            password=password,
            currentSchema=schema,
            encrypt="true",
            sslValidateCertificate="true",
            sslCryptoProvider="openssl",
            sslTrustStore=haascert
        )
    else:
        connection = dbapi.connect(host,int(port),user,password)

#
#    # Prep a cursor for SQL execution
    cursor = connection.cursor()

#    # Form an SQL statement to retrieve some data
    if 'certificate' in hana.credentials:
        cursor.execute('SELECT "tempId", "tempVal", "ts", "created" FROM "DAT368.db.data::sensors.temp"')
    else:
        cursor.execute('SELECT "tempId", "tempVal", "ts", "created" FROM "' + schema + '"."DAT368.db.data::sensors.temp"')

#    # Execute the SQL and capture the result set
    sensor_vals = cursor.fetchall()

#    # Loop through the result set and output
    for sensor_val in sensor_vals:
        output += 'sensor_val: ' + str(sensor_val[1]) + ' at: ' + str(sensor_val[2]) + '\n'
#
#    # Close the DB connection
    connection.close()
#
    # Return the results
    #return output
    return Response(output, mimetype='text/plain')

if __name__ == '__main__':
    # Run the app, listening on all IPs with our chosen port number

    # Use this version in production
    #app.run(host='0.0.0.0', port=port)

    # Enable server.py reload on changes
    # This also returns server errors in the html output (security risk)
    app.run(debug=True, host='0.0.0.0', port=port)

