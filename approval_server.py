import redis
from flask import Flask, request, jsonify

import constants

app = Flask(__name__)

redis_client = redis.StrictRedis(host="localhost", port=6379, decode_responses=True)


def get_token_details_from_redis(token):
    """
    Retrieve token details from Redis.
    """
    token_key = f"token:{token}"
    if redis_client.exists(token_key):
        return redis_client.hgetall(token_key)
    else:
        return None


def delete_token_from_redis(token):
    """
    Delete token from Redis.
    """
    redis_client.delete(f"token:{token}")
    print(f"Deleted token {token} from Redis.")


@app.route("/wificonnections/approve/", methods=["GET"])
def approve():
    token = request.args.get("token")

    token_data = get_token_details_from_redis(token)
    if not token_data:
        return jsonify({"error": "Invalid or expired token"}), 400

    user_email = token_data[constants.store_key_email]
    user_mac_id = token_data[constants.store_key_mac_id]

    # TODO: check target OS

    delete_token_from_redis(token)
    # TODO: add to whitelist
    return jsonify({"message": f"Approval successful for {user_email} ({user_mac_id})"}), 200


if __name__ == "__main__":
    app.run(debug=True)
