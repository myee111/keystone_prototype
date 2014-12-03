from flask import Flask, request, abort, jsonify

app = Flask(__name__)


@app.route('/s3/buckets', methods=['GET', 'POST'])
def get_buckets():
    if not request.json:
        abort(400)
    if request.method == 'GET':
        return 'some get request'
    if request.method == 'POST':
        access_id = request.json['access_id']
        access_secret = request.json['access_secret']
        return jsonify(access_id) + access_secret, 201

if __name__ == '__main__':
    app.run()
