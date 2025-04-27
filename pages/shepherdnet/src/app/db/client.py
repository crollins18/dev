from pymongo import MongoClient
from bson.json_util import dumps
import json

client = MongoClient('mongodb', 27017)
db = client['db']

def get_tickets():
    cursor = db.tickets.find()
    return json.loads(dumps(cursor))

def add_ticket(ticket):
    db.tickets.insert_one(ticket)