# from google.cloud import pubsub_v1
# import json

# class PubSubService:
#     def __init__(self):
#         self.subscriber = pubsub_v1.SubscriberClient()
#         self.subscription_path = self.subscriber.subscription_path('alarm-mail-app', 'gmail-subscription')

#     def start_subscription(self):
#         def callback(message):
#             print(f"Received message: {message.data}")
#             try:
#                 decoded_data = message.data.decode('utf-8')
#                 notification = json.loads(decoded_data)
#                 print(f"Parsed notification: {notification}")
#             except Exception as e:
#                 print(f"Error parsing message: {e}")
#             message.ack()

#         print(f"Starting subscription on {self.subscription_path}")
#         streaming_pull_future = self.subscriber.subscribe(self.subscription_path, callback=callback)
#         try:
#             streaming_pull_future.result()
#         except Exception as e:
#             print(f"Subscription error: {e}")
#             streaming_pull_future.cancel()