from flask import Flask, jsonify, request
from flask_cors import CORS,cross_origin
from flask_socketio import SocketIO, emit
import cv2
import base64
import threading
import json
from concurrent.futures import ThreadPoolExecutor
from ultralytics import YOLO
import time
import datetime
from werkzeug.security import check_password_hash, generate_password_hash
import jwt
from datetime import  timedelta
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event,desc
from sqlalchemy.orm import scoped_session, sessionmaker
from gevent import monkey


monkey.patch_all()


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///detection_data.db'  # SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True
db = SQLAlchemy(app)


threads = []
running_threads = {}
executor = ThreadPoolExecutor(max_workers=8)  # Use a thread pool with max 8 workers
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})
socketio = SocketIO(app, cors_allowed_origins="*",async_mode='gevent')

# Path to the JSON file
DATA_FILE = 'C:\\Users\\Vignesh R\\SafetyProjectMaster\\clientapp\\src\\data\\info.json'


# Initialize multiple YOLO models based on camera requirements
CAMERA_MODELS = {
    0: YOLO("C://Users//Vignesh R//SafetyProjectMaster//Models//fire_smoke.pt", verbose=False),
    1: YOLO("C://Users//Vignesh R//SafetyProjectMaster//Models//HD.pt", verbose=False),
    2: YOLO("C://Users//Vignesh R//SafetyProjectMaster//Models//pirate_ship.pt", verbose=False),
    3: YOLO("C://Users//Vignesh R//SafetyProjectMaster//Models//oilLeakage.pt", verbose=False), 
    4: YOLO("C://Users//Vignesh R//SafetyProjectMaster//Models//water_leakage.pt", verbose=False),
    5: YOLO("C://Users//Vignesh R//SafetyProjectMaster//Models//jumpsuit.pt", verbose=False),
    6: YOLO("C://Users//Vignesh R//SafetyProjectMaster//Models//HD.pt", verbose=False),
    7: YOLO("C://Users//Vignesh R//SafetyProjectMaster//Models//shipClass.pt", verbose=False),
}

# Path to videos for each camera
CAMERA_VIDEOS = {
    0: "C:\\Users\\Vignesh R\\SafetyProjectMaster\\Videos\\FireDetection.mp4", 
    1: "rtsp://TestUser:Test@1234@192.168.1.64:554/Streaming/Channels/101",
    2: "C:\\Users\\Vignesh R\\SafetyProjectMaster\\Videos\\PirateShip.mp4",
    3: "C:\\Users\\Vignesh R\\SafetyProjectMaster\\Videos\\oilTest.mp4",
    4: "C:\\Users\\Vignesh R\\SafetyProjectMaster\\Videos\\WaterLeakage.mp4",
    5: "C:\\Users\\Vignesh R\\SafetyProjectMaster\\Videos\\Jumpsuit.mp4",
    6: "rtsp://TestUser:Test@1234@192.168.1.64:554/Streaming/Channels/101",
    7: "C:\\Users\\Vignesh R\\SafetyProjectMaster\\Videos\\ShipCLass.mp4"
}

# JWT secret key
JWT_SECRET = 'swireshipping'
# In-memory user store (hashed passwords)
users = {
    "ship": generate_password_hash("test")
}


# Define the TicketInfo model (table)
class TicketInfo(db.Model):
    __tablename__ = 'ticket_info'
    id = db.Column(db.Integer, primary_key=True)
    object_id = db.Column(db.String(100), nullable=False)
    class_name = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    alert_message = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    confidence =  db.Column(db.String(100), nullable=False)
    acknowledge = db.Column(db.Integer,default = 0)

# Define the ObjectDetected model (table)
class ObjectDetected(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket_info.id'))
    camera_id = db.Column(db.String(50), nullable=False)
    frame_base64 = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    ticket_info = db.relationship('TicketInfo', backref='objects', lazy=True)
    
# Create the database tables inside the app context
with app.app_context():
    db.create_all()  # This will create the tables in your SQLite database
    session_factory = scoped_session(sessionmaker(bind=db.engine))
    Session = scoped_session(session_factory)
    print("Database tables created successfully.")



def add_detection(ticket_data,frame_base64):
    try:
        session = Session()
        timestamp = ticket_data.get('timestamp')
        if isinstance(timestamp, (float, int)):
            timestamp = datetime.datetime.fromtimestamp(timestamp)

        ticket_info = TicketInfo(
            object_id=ticket_data['objectID'],
            class_name=ticket_data['className'],
            severity=ticket_data['severity'],
            alert_message=ticket_data.get('alertMessage'),
            confidence=ticket_data['confidence'],
            timestamp=timestamp
        )
        print(ticket_info.object_id)
        session.add(ticket_info)
        session.commit()
        print('TicketInfo record added successfully with ID:', ticket_info.id)

        object_detected = ObjectDetected(
            ticket_id=ticket_info.id,
            camera_id=ticket_data['camera_id'],
            frame_base64=frame_base64,
            timestamp=timestamp
        )
        session.add(object_detected)
        session.commit()
        print('ObjectDetected record added successfully with ID:', object_detected.id)
    except Exception as e:
        dsession.rollback()
        print(f"Error inserting data: {e}")
    finally:
        session.close()


def find_camera_name(id):
    cameras = load_data()
    camera_names = list(map(lambda x: x["cameraName"] if x["id"] == id else None, cameras))
    camera_names = [name for name in camera_names if name is not None]
    return camera_names[0] if camera_names else "Camera not found"

def generate_jwt_token(user):
    """Generate a JWT token for the given user."""
    token = jwt.encode({    
        'user': user,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, JWT_SECRET, algorithm="HS256")
    return token

def verify_jwt_token(token):
    """Verify the JWT token and return the payload if valid."""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Routes for user authentication
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if username in users and check_password_hash(users[username], password):
        token = generate_jwt_token(username)
        return jsonify({"message": "Login successful", "token": token}), 200
    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/api/protected', methods=['GET'])
def protected_route():
    token = request.headers.get('Authorization')    
    if not token:
        return jsonify({"message": "Token missing"}), 403

    user_data = verify_jwt_token(token)
    if not user_data:
        return jsonify({"message": "Invalid or expired token"}), 403
    
    return jsonify({"message": f"Welcome {user_data['user']}! You have access to this protected route."})


@app.route('/api/ticket_info', methods=['GET'])
def get_ticket_info():
    tickets = TicketInfo.query.all()
    ticket_data = [{
        "id": ticket.id,
        "object_id": ticket.object_id,
        "class_name": ticket.class_name,
        "severity": ticket.severity,
        "alert_message": ticket.alert_message,
        "timestamp": ticket.timestamp
    } for ticket in tickets]
    return jsonify(ticket_data)

@app.route('/api/acknowledge_entry/<int:ticket_id>', methods=['POST'])
def acknowledge_entry(ticket_id):
    try:
        # Fetch ticket by ticket_id using session.get()
        ticket = db.session.get(TicketInfo, ticket_id)
 
        if not ticket:
            return jsonify({"message": "Ticket not found"}), 404
       
        # Update the acknowledge field
        ticket.acknowledge = 1
 
        # Commit changes to the database
        db.session.commit()
 
        # Verify changes by logging
        print(f"Ticket {ticket_id} acknowledged. Acknowledge flag: {ticket.acknowledge}")
       
        # Return a success message
        return jsonify({"message": "Ticket acknowledged successfully!"}), 200
 
    except Exception as e:
        # Rollback in case of any errors and log the exception
        db.session.rollback()
        print(f"Error occurred: {str(e)}")
        return jsonify({"message": f"Error occurred: {str(e)}"}), 500


@app.route('/api/camera_based_tickets/<int:cam_id>', methods=['GET'])
def camera_basedTickets(cam_id):
    if cam_id != None:
        results = (
            db.session.query(TicketInfo, ObjectDetected)
            .join(ObjectDetected, TicketInfo.id == ObjectDetected.ticket_id )
            .filter(ObjectDetected.camera_id == cam_id)
            .filter(TicketInfo.acknowledge == 0)
            .order_by(desc(TicketInfo.timestamp))
            .all()  
        )
 
    
 
    data = [{
        "ticket_id": ticket.id,
        "object_id": ticket.object_id,
        "class_name": ticket.class_name,
        "severity": ticket.severity,
        "alert_message": ticket.alert_message,
        "ticket_timestamp": ticket.timestamp,
        "camera_id": obj.camera_id,
        "object_timestamp": obj.timestamp,
        
    } for ticket, obj in results]
   
    return jsonify(data)

    


@app.route('/api/ticket_page_filter/<int:filter>', methods=['GET'])
def ticket_page_filter(filter):
    if filter == 0:
        results = (
            db.session.query(TicketInfo, ObjectDetected)
            .join(ObjectDetected, TicketInfo.id == ObjectDetected.ticket_id )
            .filter(TicketInfo.severity == 'normal')
            .filter(TicketInfo.acknowledge == 0)
            .order_by(desc(TicketInfo.timestamp))
            .all()  
        )
 
    if filter == 1:
        results = (
            db.session.query(TicketInfo, ObjectDetected)
            .join(ObjectDetected, TicketInfo.id == ObjectDetected.ticket_id)
            .filter(TicketInfo.severity == 'danger')
            .filter(TicketInfo.acknowledge == 0)
            .order_by(desc(TicketInfo.timestamp))
            .all()  
        )
 
    if filter == 2:
        results = (
            db.session.query(TicketInfo, ObjectDetected)
            .join(ObjectDetected, TicketInfo.id == ObjectDetected.ticket_id)
            .filter(TicketInfo.severity == 'high alert')
            .filter(TicketInfo.acknowledge == 0)
            .order_by(desc(TicketInfo.timestamp))
            .all()  
        )
 
    data = [{
        "ticket_id": ticket.id,
        "object_id": ticket.object_id,
        "class_name": ticket.class_name,
        "severity": ticket.severity,
        "alert_message": ticket.alert_message,
        "ticket_timestamp": ticket.timestamp,
        "camera_id": obj.camera_id,
        "object_timestamp": obj.timestamp,
        
    } for ticket, obj in results]
   
    return jsonify(data)

    

@app.route('/api/object_detected', methods=['GET'])
def get_object_detected():
    objects = ObjectDetected.query.all()
    
    object_data = [{
        "id": obj.id,
        "ticket_id": obj.ticket_id,
        "camera_id": obj.camera_id,
        "timestamp": obj.timestamp,
        "frame_base64": obj.frame_base64
    } for obj in objects]
    return jsonify(object_data)

@app.route('/api/ticket_with_object', methods=['GET'])
def get_ticket_with_object():
    # Perform a join query where ticket.id == object.ticket_id
    results = (
        db.session.query(TicketInfo, ObjectDetected)
        .join(ObjectDetected, TicketInfo.id == ObjectDetected.ticket_id)
        .all()
    )
 
    # Prepare the data in the required JSON format
    data = [{
        "ticket_id": ticket.id,
        "object_id": ticket.object_id,
        "class_name": ticket.class_name,
        "severity": ticket.severity,
        "alert_message": ticket.alert_message,
        "ticket_timestamp": ticket.timestamp,
        "camera_id": obj.camera_id,
        "object_timestamp": obj.timestamp,
        "frame_base64": obj.frame_base64
    } for ticket, obj in results]
   
    return jsonify(data)
 

@app.route('/api/detection_table_data', methods=['GET'])
def detection_table_data():
    # Perform a join query where ticket.id == object.ticket_id
    results = (
        db.session.query(TicketInfo, ObjectDetected)
        .join(ObjectDetected, TicketInfo.id == ObjectDetected.ticket_id)
        .all()
    )
    
    # Prepare the data in the required JSON format
    data = [{
        "ticket_id": ticket.id,
        "object_id": ticket.object_id,
        "class_name": ticket.class_name,
        "severity": ticket.severity,
        "alert_message": ticket.alert_message,
        "ticket_timestamp": ticket.timestamp,
        "camera_id": obj.camera_id,
        "object_timestamp": obj.timestamp
    } for ticket, obj in results]
    
    return jsonify(data)

@app.route('/api/count_by_severity', methods=['GET'])
def count_by_severity():
    severity_counts = db.session.query(
        TicketInfo.severity,
        db.func.count(TicketInfo.id).label('count')
    ).group_by(TicketInfo.severity).all()

    result = [{
        "severity": data.severity,
        "count": data.count
    } for data in severity_counts]

    return jsonify(result)




@app.route('/api/ticket_object_id/<int:ticket_id>', methods=['GET'])
def ticket_object_id(ticket_id):
    # Query the TicketInfo table for the specific ticket_id
    ticket = TicketInfo.query.filter_by(id=ticket_id).first()
    
    # Check if the ticket exists
    if not ticket:
        return jsonify({"error": "No ticket found for the specified ticket_id"}), 404
    
    # Query the ObjectDetected table for objects related to this ticket_id
    obj = ObjectDetected.query.filter_by(ticket_id=ticket_id).first()

    # Prepare the data for response
    data = {
        "ticket_id": ticket.id,
        "object_id": ticket.object_id,
        "class_name": ticket.class_name,
        "severity": ticket.severity,
        "alert_message": ticket.alert_message,
        "ticket_timestamp": ticket.timestamp,
        "frame_base64": obj.frame_base64,
        "camera_id": obj.camera_id,
       
    }
    
    return jsonify(data)


@app.route('/api/report', methods=['GET'])
def get_report():
    # Aggregate count of detections by class name and severity
    report_data = db.session.query(
        TicketInfo.class_name,
        TicketInfo.severity,
        db.func.count(TicketInfo.id).label('count')
    ).group_by(TicketInfo.class_name, TicketInfo.severity).all()

    report = [{
        "class_name": data.class_name,
        "severity": data.severity,
        "count": data.count
    } for data in report_data]

    return jsonify(report)


@app.route('/api/graph_data', methods=['GET'])
def get_graph_data():
    # Aggregate count of detections per class
    graph_data = db.session.query(
        TicketInfo.class_name,
        db.func.count(TicketInfo.id).label('count')
    ).group_by(TicketInfo.class_name).all()

    graph = [{
        "class_name": data.class_name,
        "count": data.count
    } for data in graph_data]

    return jsonify(graph)

# Load data from JSON file
def load_data():
    with open(DATA_FILE, 'r') as file:
        return json.load(file)

# Save data to JSON file
def save_data(data):
    with open(DATA_FILE, 'w') as file:
        json.dump(data, file, indent=4)

# Camera management routes
@app.route('/cameras', methods=['GET'])
def get_cameras():
    data = load_data()
    return jsonify(data)

@app.route('/cameras', methods=['POST'])
def add_camera():
    data = load_data()
    new_camera = request.json
    data.append(new_camera)
    save_data(data)
    return jsonify(data)

@app.route('/cameras/<int:index>', methods=['PUT'])
def update_camera(index):
    data = load_data()
    updated_camera = request.json
    data[index] = updated_camera
    save_data(data)
    return jsonify(data)

@app.route('/cameras/<int:index>', methods=['DELETE'])
def delete_camera(index):
    data = load_data()
    data.pop(index) 
    save_data(data)
    return jsonify(data)

@app.route('/start-all', methods=['POST'])
def start_all_cameras():
    global threads, running_threads
    for source, model in CAMERA_MODELS.items():
        if source in CAMERA_VIDEOS and source not in running_threads:
            input_path = CAMERA_VIDEOS[source]
            thread = CameraThread(cam_id=input_path, source=source, model=model)
            executor.submit(thread.run)  # Submit to thread pool
            running_threads[source] = thread
    return jsonify({"status": "started all cameras"})

@app.route('/stop-all', methods=['POST'])
def stop_all_cameras():
    global running_threads
    try:
        for cam_id, thread in list(running_threads.items()):
            if thread.is_alive():
                print(f"Stopping camera thread: {cam_id}")
                thread.stop()
                thread.join(timeout=5)
            else:
                print(f"Camera thread {cam_id} already stopped")
        running_threads.clear()
        return jsonify({"status": "stopped all cameras"})
    except Exception as e:
        print(f"Error stopping cameras: {e}")
        return jsonify({"error": "Failed to stop all cameras", "details": str(e)}), 500


@app.route('/start-camera/<int:camera_id>', methods=['POST'])
def start_camera(camera_id):
    global CAMERA_MODELS, CAMERA_VIDEOS, threads
    if camera_id in running_threads:
        return jsonify({"status": "Camera already running"})

    model = CAMERA_MODELS.get(camera_id)
    input_path = CAMERA_VIDEOS.get(camera_id)
    
    if model and input_path:
        thread = CameraThread(cam_id=input_path, source=camera_id, model=model)
        executor.submit(thread.run)  # Use thread pool to manage camera threads
        running_threads[camera_id] = thread
        return jsonify({"status": f"Started camera {camera_id}"})
    
    return jsonify({"status": "Camera or model not found"})

@app.route('/ships', methods=['GET'])
def get_ships():
    ships = [
        {"id": 1, "name": "Ship 1", "latitude": 37.7749, "longitude": -122.4194, "location": "San Francisco", "hasDetection": False},
        {"id": 2, "name": "Ship 2", "latitude": 34.0522, "longitude": -118.2437, "location": "Los Angeles", "hasDetection": True},
        {"id": 3, "name": "Ship 3", "latitude": 40.7128, "longitude": -74.0060, "location": "New York", "hasDetection": False},
        {"id": 4, "name": "Ship 4", "latitude": 51.5074, "longitude": -0.1278, "location": "London", "hasDetection": True},
        {"id": 5, "name": "Ship 5", "latitude": 35.6895, "longitude": 139.6917, "location": "Tokyo", "hasDetection": True},
    ]
    return jsonify(ships)
# Helper class for camera thread management
class CameraThread(threading.Thread):
    def __init__(self, cam_id, source, model):
        threading.Thread.__init__(self)
        self.source = source
        self.cam_id = cam_id
        self.model = model
        self.running = True
        self.lock = threading.Lock()  # Use a lock for thread-safe flag update
        self.tickets = []
    def run(self):
        cap = cv2.VideoCapture(self.cam_id)
        #fps = cap.get(cv2.CAP_PROP_FPS) or 30
        frame_interval = max(int(fps // 5), 1)  # Skip frames for better performance
        frame_interval = int(fps) # One frame per second
        frame_count = 0
        last_detection_time = {}

        while self.is_running() and cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break

            # Process every N frames
            if frame_count % frame_interval == 0:
                results = self.model.track(frame)
                annotated_frame = results[0].plot()
                
                # Convert frame to JPEG and base64 for sending via WebSocket
                _, buffer = cv2.imencode('.jpg', annotated_frame)
                frame_data = base64.b64encode(buffer).decode('utf-8')
                
                # Send frame via WebSocket
                socketio.emit(f'frame{self.source}', frame_data, namespace='/')

                # Emit object detection data
                for result in results:
                    for box in result.boxes:
                        obj_id = int(box.id[0]) if box.id else "unknown"
                        class_id = int(box.cls[0]) if box.cls[0] != None else -1
                        class_name = result.names[class_id] if class_id in result.names else "unknown"
                        confidence = float(box.conf[0]) * 100 if box.conf else 0
                        cameraName = find_camera_name(self.source)
                        if class_name in ["NO-Hardhat", "NO-Safety Vest"]:
                            severity = "high alert"
                        elif class_name in ["fire", "smoke","pirate ship"]:
                            severity = "danger"
                        else:
                            severity = "normal"
                        alert_message = f"Alert Message - {class_name} (ID: {obj_id})"
                        current_time = time.time()
                        if obj_id not in last_detection_time or current_time - last_detection_time[obj_id] > 5:
                            last_detection_time[obj_id] = current_time
                            ticket_info = {
                                "camera_id": self.source,
                                "objectID": obj_id,
                                "className": class_name,
                                'alertMessage': alert_message,
                                "confidence": f"{class_name} has detected in {cameraName} with confidence of : {confidence:.2f}%",  
                                'severity' : severity,
                                'source' : self.source,
                                "timestamp": current_time
                              
                            }
                           
                            self.tickets.append(ticket_info)
                            if(class_name != "unknown"):
                                socketio.emit('object_detected', ticket_info, namespace='/')
                                socketio.emit('ticketData', self.tickets, namespace='/')
                                add_detection(ticket_info,frame_data)


            frame_count += 1
            time.sleep(1 / fps)

        cap.release()  # Release the camera when done

    def is_running(self):
        """Check if the thread should be running in a thread-safe way."""
        with self.lock:
            return self.running

    def stop(self):
        """Stop the thread in a thread-safe way."""
        with self.lock:
            self.running = False


if __name__ == '__main__':
    from gevent.pywsgi import WSGIServer
    from geventwebsocket.handler import WebSocketHandler
    
    # Use gevent's WSGIServer to serve the app
    http_server = WSGIServer(('0.0.0.0', 7890), app, handler_class=WebSocketHandler)
    http_server.serve_forever()