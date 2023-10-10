from run import app
from flask import jsonify, render_template, make_response
@app.route('/')
def index():
    ref = make_response(render_template('index.html',),200)
    return ref
