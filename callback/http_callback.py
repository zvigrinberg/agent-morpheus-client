from flask import Flask, request
import os
import logging

logger = logging.getLogger(__name__)

class HttpCallback:

  def logging_callback(self, data):
    logger.info('Received %s', data)

  def __init__(self):
    self.api = Flask(__name__)
    self.api.add_url_rule('/results', 'result_callback', self.result_callback, methods=['POST'])
    self.port = os.getenv('CALLBACK_PORT', 5000)
    self.on_receive = self.logging_callback

  def result_callback(self):
    logger.info('Received request')
    data = request.get_json()
    self.on_receive(data)
    return "Success", 201

  def serve(self, on_receive):
    if on_receive is not None:
      self.on_receive = on_receive
    self.api.run(host='0.0.0.0', port=self.port)