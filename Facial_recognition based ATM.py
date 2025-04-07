# facial_recognition_atm.py
"""
Enhanced Facial Recognition ATM System
A secure, user-friendly ATM application with facial recognition authentication
"""

import os
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox
import datetime
import logging
import cv2
import threading
import numpy as np
import time
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='atm_system.log'
)
logger = logging.getLogger('facial_recognition_atm')

# Constants
APP_TITLE = "Secure Facial Recognition ATM"
DB_PATH = "data/atm_database.db"
FACE_DATA_DIR = "data/face_data"
LOG_DIR = "data/logs"
CONFIG = {
    "face_detection_confidence": 0.7,
    "face_recognition_threshold": 0.6,
    "max_login_attempts": 3,
    "session_timeout": 60,  # seconds
    "min_deposit": 1,
    "max_withdrawal": 1000,
    "face_capture_count": 20  # Number of faces to capture during registration
}

# Ensure directories exist
for directory in [os.path.dirname(DB_PATH), FACE_DATA_DIR, LOG_DIR]:
    Path(directory).mkdir(parents=True, exist_ok=True)

# Theme colors
THEME = {
    "primary": "#1976D2",      # Primary blue
    "primary_dark": "#0D47A1", # Darker blue
    "accent": "#FF5722",       # Orange accent
    "text_light": "#FFFFFF",   # White text
    "text_dark": "#212121",    # Dark text
    "background": "#F5F5F5",   # Light gray background
    "success": "#4CAF50",      # Green for success
    "error": "#F44336",        # Red for errors
    "warning": "#FFC107"       # Yellow for warnings
}


class Database:
    """Database manager for the ATM system."""
    
    def __init__(self, db_path: str):
        """Initialize database connection and ensure tables exist."""
        self.db_path = db_path
        self._create_tables()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _create_tables(self) -> None:
        """Create necessary database tables if they don't exist."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Users table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    face_encoding_path TEXT,
                    status TEXT DEFAULT 'active',
                    last_login DATETIME
                )
                ''')
                
                # Accounts table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    account_type TEXT DEFAULT 'checking',
                    balance REAL DEFAULT 0.0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
                ''')
                
                # Transactions table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    account_id INTEGER NOT NULL,
                    transaction_type TEXT NOT NULL,
                    amount REAL NOT NULL,
                    balance_after REAL NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    description TEXT,
                    FOREIGN KEY (account_id) REFERENCES accounts(id)
                )
                ''')
                
                # Security logs table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    ip_address TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    details TEXT
                )
                ''')
                
                conn.commit()
                logger.info("Database tables created successfully")
                
        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
            messagebox.showerror("Database Error", "Failed to initialize database. See logs for details.")
    
    def create_user(self, username: str, face_encoding_path: str) -> bool:
        """Create a new user with a checking account."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                # Insert user
                cursor.execute(
                    "INSERT INTO users (username, face_encoding_path) VALUES (?, ?)",
                    (username, face_encoding_path)
                )
                user_id = cursor.lastrowid
                
                # Create checking account for user
                cursor.execute(
                    "INSERT INTO accounts (user_id, account_type) VALUES (?, ?)",
                    (user_id, "checking")
                )
                
                # Log the account creation
                self.log_security_event(username, "user_creation", "success")
                
                return True
                
        except sqlite3.IntegrityError:
            logger.warning(f"Attempted to create duplicate user: {username}")
            self.log_security_event(username, "user_creation", "failed", details="Username already exists")
            return False
            
        except sqlite3.Error as e:
            logger.error(f"Error creating user {username}: {e}")
            self.log_security_event(username, "user_creation", "error", details=str(e))
            return False
    
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user details by username."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM users WHERE username = ? AND status = 'active'",
                    (username,)
                )
                user = cursor.fetchone()
                return dict(user) if user else None
                
        except sqlite3.Error as e:
            logger.error(f"Error retrieving user {username}: {e}")
            return None
    
    def get_account_by_user_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get account details by user ID."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM accounts WHERE user_id = ?",
                    (user_id,)
                )
                account = cursor.fetchone()
                return dict(account) if account else None
                
        except sqlite3.Error as e:
            logger.error(f"Error retrieving account for user {user_id}: {e}")
            return None
    
    def update_balance(self, account_id: int, new_balance: float) -> bool:
        """Update account balance."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE accounts SET balance = ? WHERE id = ?",
                    (new_balance, account_id)
                )
                return True
                
        except sqlite3.Error as e:
            logger.error(f"Error updating balance for account {account_id}: {e}")
            return False
    
    def record_transaction(self, account_id: int, transaction_type: str, 
                           amount: float, balance_after: float, description: str = "") -> int:
        """Record a transaction and return the transaction ID."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO transactions 
                       (account_id, transaction_type, amount, balance_after, description) 
                       VALUES (?, ?, ?, ?, ?)""",
                    (account_id, transaction_type, amount, balance_after, description)
                )
                transaction_id = cursor.lastrowid
                return transaction_id
                
        except sqlite3.Error as e:
            logger.error(f"Error recording transaction for account {account_id}: {e}")
            return -1
    
    def get_recent_transactions(self, account_id: int, limit: int = 5) -> List[Dict[str, Any]]:
        """Get recent transactions for an account."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """SELECT * FROM transactions 
                       WHERE account_id = ? 
                       ORDER BY timestamp DESC LIMIT ?""",
                    (account_id, limit)
                )
                transactions = cursor.fetchall()
                return [dict(t) for t in transactions]
                
        except sqlite3.Error as e:
            logger.error(f"Error retrieving transactions for account {account_id}: {e}")
            return []
    
    def log_security_event(self, username: str, action: str, status: str, 
                           ip_address: str = "local", details: str = "") -> None:
        """Log a security-related event."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO security_logs 
                       (username, action, status, ip_address, details) 
                       VALUES (?, ?, ?, ?, ?)""",
                    (username, action, status, ip_address, details)
                )
                
        except sqlite3.Error as e:
            logger.error(f"Error logging security event: {e}")
    
    def update_last_login(self, username: str) -> None:
        """Update user's last login timestamp."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ?",
                    (username,)
                )
                
        except sqlite3.Error as e:
            logger.error(f"Error updating last login for {username}: {e}")


class FacialRecognition:
    """Handles facial recognition operations."""
    
    def __init__(self, data_dir: str):
        """Initialize facial recognition system."""
        self.data_dir = data_dir
        
        # Load face detection and recognition models
        try:
            self.face_detector = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
            if self.face_detector.empty():
                logger.error("Error loading face detection model")
                raise ValueError("Failed to load face detection model")
                
            # In a production system, we'd use a more sophisticated face recognition model
            # For this demo, we'll use a simplified approach with face embeddings
            
            logger.info("Facial recognition system initialized")
            
        except Exception as e:
            logger.error(f"Error initializing facial recognition: {e}")
            raise
    
    def detect_faces(self, frame) -> List:
        """Detect faces in the given frame."""
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = self.face_detector.detectMultiScale(
            gray, 
            scaleFactor=1.1, 
            minNeighbors=5,
            minSize=(30, 30)
        )
        return faces
    
    def capture_face_data(self, username: str) -> Optional[str]:
        """Capture face data for a new user."""
        if not username or not username.strip():
            logger.warning("Invalid username provided for face capture")
            return None
            
        safe_username = ''.join(c for c in username if c.isalnum() or c in '._- ')
        user_data_path = os.path.join(self.data_dir, f"{safe_username}")
        os.makedirs(user_data_path, exist_ok=True)
        
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            logger.error("Failed to open camera")
            return None
            
        faces_captured = 0
        face_data = []
        
        try:
            while faces_captured < CONFIG["face_capture_count"]:
                ret, frame = cap.read()
                if not ret:
                    continue
                    
                faces = self.detect_faces(frame)
                
                if len(faces) == 1:  # Ensure only one face in frame
                    x, y, w, h = faces[0]
                    face_img = frame[y:y+h, x:x+w]
                    
                    # In a real system, we'd extract face embeddings
                    # For this demo, we'll just save the face images
                    face_file = os.path.join(user_data_path, f"face_{faces_captured}.jpg")
                    cv2.imwrite(face_file, face_img)
                    face_data.append(face_img)
                    
                    faces_captured += 1
                    time.sleep(0.2)  # Small delay between captures
                
                # Display progress in camera feed
                cv2.putText(frame, f"Capturing: {faces_captured}/{CONFIG['face_capture_count']}", 
                           (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
                cv2.imshow("Face Registration", frame)
                
                if cv2.waitKey(1) & 0xFF == ord('q'):
                    break
                    
            cv2.destroyAllWindows()
            
            if faces_captured == CONFIG["face_capture_count"]:
                # Save metadata about the face capture
                with open(os.path.join(user_data_path, "metadata.txt"), "w") as f:
                    f.write(f"username: {username}\n")
                    f.write(f"created: {datetime.datetime.now().isoformat()}\n")
                    f.write(f"faces_captured: {faces_captured}\n")
                
                logger.info(f"Successfully captured face data for {username}")
                return user_data_path
            else:
                logger.warning(f"Incomplete face data capture for {username}")
                return None
                
        except Exception as e:
            logger.error(f"Error capturing face data: {e}")
            return None
            
        finally:
            cap.release()
    
    def authenticate_user(self) -> Optional[str]:
        """Authenticate a user with facial recognition."""
        # Get list of enrolled users
        enrolled_users = []
        for username_dir in os.listdir(self.data_dir):
            user_path = os.path.join(self.data_dir, username_dir)
            if os.path.isdir(user_path):
                enrolled_users.append((username_dir, user_path))
                
        if not enrolled_users:
            logger.warning("No enrolled users found")
            return None
            
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            logger.error("Failed to open camera")
            return None
            
        start_time = time.time()
        attempts = 0
        last_display_time = 0
        authenticated_username = None
        
        try:
            while time.time() - start_time < 30:  # 30 seconds timeout
                ret, frame = cap.read()
                if not ret:
                    continue
                current_time = time.time()
                if current_time - last_display_time > 0.5:  # Update message every 0.5 seconds
                    time_left = int(30 - (current_time - start_time))
                    cv2.putText(frame, f"Looking for registered faces... ({time_left}s)", 
                               (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
                    last_display_time = current_time
                
                cv2.imshow("Authentication", frame)
                
                faces = self.detect_faces(frame)
                if len(faces) == 1:  # Ensure only one face in frame
                    x, y, w, h = faces[0]
                    face_img = frame[y:y+h, x:x+w]
                    
                    # In a real system, we'd use face embeddings and proper distance metrics
                    # For this demo, we'll use a simplified approach with template matching
                    max_confidence = 0
                    best_match = None
                    
                    # Process each enrolled user
                    for username, user_path in enrolled_users:
                        # Get the user's face images
                        face_files = [f for f in os.listdir(user_path) if f.startswith("face_") and f.endswith(".jpg")]
                        if not face_files:
                            continue
                            
                        # Calculate confidence based on template matching
                        user_confidence = 0
                        for face_file in face_files:
                            template = cv2.imread(os.path.join(user_path, face_file), cv2.IMREAD_GRAYSCALE)
                            if template is None:
                                continue
                                
                            # Resize for comparison
                            face_gray = cv2.cvtColor(face_img, cv2.COLOR_BGR2GRAY)
                            face_gray = cv2.resize(face_gray, (template.shape[1], template.shape[0]))
                            
                            # Template matching
                            result = cv2.matchTemplate(face_gray, template, cv2.TM_CCOEFF_NORMED)
                            _, confidence, _, _ = cv2.minMaxLoc(result)
                            user_confidence = max(user_confidence, confidence)
                        
                        if user_confidence > max_confidence:
                            max_confidence = user_confidence
                            best_match = username
                    
                    # Check if confidence is above threshold
                    if max_confidence > CONFIG["face_recognition_threshold"]:
                        authenticated_username = best_match
                        logger.info(f"User authenticated: {authenticated_username} (confidence: {max_confidence:.2f})")
                        break
                    else:
                        attempts += 1
                        if attempts >= CONFIG["max_login_attempts"]:
                            logger.warning("Max authentication attempts reached")
                            break
                
                if cv2.waitKey(1) & 0xFF == ord('q'):
                    break
                    
            cv2.destroyAllWindows()
            return authenticated_username
            
        except Exception as e:
            logger.error(f"Error during authentication: {e}")
            return None
            
        finally:
            cap.release()


class ATMFrame(ttk.Frame):
    """Base class for all ATM frames with common styling and functionality."""
    
    def __init__(self, parent, controller):
        """Initialize the frame with common styling."""
        super().__init__(parent, style="ATM.TFrame")
        self.controller = controller
        self.parent = parent
        
        self.grid_rowconfigure(0, weight=1)  # Allow rows to expand
        self.grid_columnconfigure(0, weight=1)  # Allow columns to expand
        
        # Set up the frame grid
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        
        # Create container for content
        self.content_frame = ttk.Frame(self, padding=20, style="Content.TFrame")
        self.content_frame.grid(row=0, column=0, sticky="nsew")
        self.content_frame.columnconfigure(0, weight=1)
        
        # Create header if needed
        self.header_var = tk.StringVar()
        self.header = ttk.Label(
            self.content_frame,
            textvariable=self.header_var,
            style="Header.TLabel"
        )
        self.header.grid(row=0, column=0, pady=(0, 20), sticky="nsew")
        
        # Create footer with navigation buttons
        self.footer_frame = ttk.Frame(self.content_frame, style="Footer.TFrame")
        self.footer_frame.grid(row=99, column=0, pady=(20, 0), sticky="ew")
        
        # Add common navigation buttons
        self.home_button = ttk.Button(
            self.footer_frame,
            text="Home",
            command=lambda: self.controller.show_frame("WelcomePage"),
            style="Navigation.TButton"
        )
        
        self.exit_button = ttk.Button(
            self.footer_frame,
            text="Exit",
            command=self.controller.quit,
            style="Danger.TButton"
        )
        
        # Place footer buttons
        self.home_button.pack(side="left", padx=5)
        self.exit_button.pack(side="right", padx=5)
    
    
    
    def set_header(self, text):
        """Set the header text."""
        self.header_var.set(text)
    
    def clear_fields(self):
        """Clear input fields - to be implemented by subclasses."""
        pass
    
    def display_message(self, message, message_type="info"):
        """Display a message to the user."""
        colors = {
            "info": THEME["primary"],
            "success": THEME["success"],
            "error": THEME["error"],
            "warning": THEME["warning"]
        }
        
        messagebox.showinfo("Message", message) if message_type == "info" else \
        messagebox.showwarning("Warning", message) if message_type == "warning" else \
        messagebox.showerror("Error", message) if message_type == "error" else \
        messagebox.showinfo("Success", message)


class WelcomePage(ATMFrame):
    """Welcome page with options to register or log in."""
    
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.set_header("Welcome to Secure Facial Recognition ATM")
        
        # Hide the home button on welcome page
        self.home_button.pack_forget()

        self.grid_rowconfigure(0, weight=1)  # Allow rows to expand
        self.grid_columnconfigure(0, weight=1)  # Allow columns to expand

        
        # Create buttons frame
        buttons_frame = ttk.Frame(self.content_frame, style="Content.TFrame")
        buttons_frame.grid(row=1, column=0, pady=20, sticky="nsew")
        buttons_frame.columnconfigure(0, weight=1)
        
        # Add logo or image (placeholder)
        logo_label = ttk.Label(
            buttons_frame,
            text="🏦",  # Bank emoji as placeholder
            font=("Arial", 72),
            anchor="center"
        )
        logo_label.grid(row=0, column=0, pady=20)
        
        # Welcome message
        welcome_message = ttk.Label(
            buttons_frame,
            text="Secure Banking with Facial Recognition",
            style="SubHeader.TLabel"
        )
        welcome_message.grid(row=1, column=0, pady=10)
        
        # Create new user button
        register_button = ttk.Button(
            buttons_frame,
            text="Register New User",
            command=lambda: controller.show_frame("RegistrationPage"),
            style="Primary.TButton"
        )
        register_button.grid(row=2, column=0, pady=10, ipady=10, ipadx=20)
        
        # Login button
        login_button = ttk.Button(
            buttons_frame,
            text="Login",
            command=lambda: controller.show_frame("LoginPage"),
            style="Primary.TButton"
        )
        login_button.grid(row=3, column=0, pady=10, ipady=10, ipadx=20)
        
        # Version info
        version_label = ttk.Label(
            self.content_frame,
            text="Secure ATM v1.0",
            style="Small.TLabel"
        )
        version_label.grid(row=98, column=0, pady=(20, 0), sticky="e")
        


class RegistrationPage(ATMFrame):
    """Page for registering new users."""
    
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.set_header("Register New User")

        self.grid_rowconfigure(0, weight=1)  # Allow rows to expand
        self.grid_columnconfigure(0, weight=1)  # Allow columns to expand

        
        # User details form
        form_frame = ttk.Frame(self.content_frame, style="Content.TFrame")
        form_frame.grid(row=1, column=0, pady=20, sticky="nsew")
        form_frame.columnconfigure(1, weight=1)
        
        # Username field
        username_label = ttk.Label(
            form_frame,
            text="Username:",
            style="Label.TLabel"
        )
        username_label.grid(row=0, column=0, pady=10, sticky="w")
        
        self.username_var = tk.StringVar()
        username_entry = ttk.Entry(
            form_frame,
            textvariable=self.username_var,
            width=30
        )
        username_entry.grid(row=0, column=1, pady=10, sticky="ew")
        
        # Face capture instructions
        instructions = ttk.Label(
            form_frame,
            text="After entering your username, click 'Capture Face' to register your face.\n"
                 "The system will take multiple images for better recognition.",
            style="Instruction.TLabel",
            wraplength=400
        )
        instructions.grid(row=1, column=0, columnspan=2, pady=20)
        
        # Capture face button
        capture_button = ttk.Button(
            form_frame,
            text="Capture Face",
            command=self.capture_face,
            style="Primary.TButton"
        )
        capture_button.grid(row=2, column=0, columnspan=2, pady=10, ipady=5, ipadx=10)
        
        # Status message
        self.status_var = tk.StringVar()
        status_label = ttk.Label(
            form_frame,
            textvariable=self.status_var,
            style="Status.TLabel"
        )
        status_label.grid(row=3, column=0, columnspan=2, pady=10)
    
    def capture_face(self):
        """Capture user's face data for registration."""
        username = self.username_var.get().strip()
        
        if not username:
            self.status_var.set("Please enter a username")
            return
            
        # Check if username already exists
        user = self.controller.db.get_user_by_username(username)
        if user:
            self.status_var.set("Username already exists. Please choose a different one.")
            return
            
        # Update status
        self.status_var.set("Initializing camera...")
        self.update()
        
        # Start face capture in a separate thread
        def capture_thread():
            try:
                face_data_path = self.controller.face_system.capture_face_data(username)
                
                if face_data_path:
                    # Register user in database
                    success = self.controller.db.create_user(username, face_data_path)
                    
                    if success:
                        self.status_var.set("Registration successful! You can now log in.")
                        # Clear the form after successful registration
                        self.username_var.set("")
                    else:
                        self.status_var.set("Error registering user. Please try again.")
                else:
                    self.status_var.set("Face capture failed. Please try again.")
                    
            except Exception as e:
                logger.error(f"Error during face capture: {e}")
                self.status_var.set("An error occurred. Please try again.")
        
        threading.Thread(target=capture_thread).start()


class LoginPage(ATMFrame):
    """Page for user login via facial recognition."""
    
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.set_header("Login")

        self.grid_rowconfigure(0, weight=1)  # Allow rows to expand
        self.grid_columnconfigure(0, weight=1)  # Allow columns to expand

        
        # Login instructions
        instructions_frame = ttk.Frame(self.content_frame, style="Content.TFrame")
        instructions_frame.grid(row=1, column=0, pady=20, sticky="nsew")
        
        instructions = ttk.Label(
            instructions_frame,
            text="Please position your face in the camera frame.\n"
                 "The system will attempt to recognize you.",
            style="Instruction.TLabel",
            wraplength=400
        )
        instructions.grid(row=0, column=0, pady=20)
        
        # Start camera button
        camera_button = ttk.Button(
            instructions_frame,
            text="Start Camera",
            command=self.start_authentication,
            style="Primary.TButton"
        )
        camera_button.grid(row=1, column=0, pady=10, ipady=5, ipadx=10)
        
        # Status message
        self.status_var = tk.StringVar()
        status_label = ttk.Label(
            instructions_frame,
            textvariable=self.status_var,
            style="Status.TLabel"
        )
        status_label.grid(row=2, column=0, pady=10)
    
    def start_authentication(self):
        """Start the facial authentication process."""
        self.status_var.set("Initializing camera...")
        self.update()
        
        # Start authentication in a separate thread
        def authenticate_thread():
            try:
                username = self.controller.face_system.authenticate_user()
                
                if username:
                    # Update last login time
                    self.controller.db.update_last_login(username)
                    
                    # Log successful login
                    self.controller.db.log_security_event(
                        username, "login", "success", details="Facial recognition"
                    )
                    
                    # Set current user in controller
                    self.controller.set_current_user(username)
                    
                    # Show account page
                    self.controller.after(0, lambda: self.controller.show_frame("AccountPage"))
                    
                    # Clear status
                    self.status_var.set("")
                else:
                    self.status_var.set("Authentication failed. Please try again.")
                    
                    # Log failed login attempt
                    self.controller.db.log_security_event(
                        "unknown", "login", "failed", details="Facial recognition failed"
                    )
                    
            except Exception as e:
                logger.error(f"Error during authentication: {e}")
                self.status_var.set("An error occurred. Please try again.")
        
        threading.Thread(target=authenticate_thread).start()


class AccountPage(ATMFrame):
    """Main account page showing balance and transaction options."""
    
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.set_header("Account Summary")

        self.grid_rowconfigure(0, weight=1)  # Allow rows to expand
        self.grid_columnconfigure(0, weight=1)  # Allow columns to expand

        
        # Account info frame
        self.account_frame = ttk.Frame(self.content_frame, style="Content.TFrame")
        self.account_frame.grid(row=1, column=0, pady=10, sticky="nsew")
        self.account_frame.columnconfigure(0, weight=1)
        
        # Welcome message
        self.welcome_var = tk.StringVar()
        welcome_label = ttk.Label(
            self.account_frame,
            textvariable=self.welcome_var,
            style="SubHeader.TLabel"
        )
        welcome_label.grid(row=0, column=0, pady=10, sticky="w")
        
        # Balance display
        balance_frame = ttk.Frame(self.account_frame, style="Card.TFrame", padding=10)
        balance_frame.grid(row=1, column=0, pady=10, sticky="ew")
        
        balance_label = ttk.Label(
            balance_frame,
            text="Current Balance:",
            style="Label.TLabel"
        )
        balance_label.grid(row=0, column=0, sticky="w")
        
        self.balance_var = tk.StringVar()
        balance_amount = ttk.Label(
            balance_frame,
            textvariable=self.balance_var,
            style="Balance.TLabel"
        )
        balance_amount.grid(row=0, column=1, padx=10, sticky="e")
        
        # Transaction options
        options_frame = ttk.Frame(self.account_frame, style="Content.TFrame")
        options_frame.grid(row=2, column=0, pady=20, sticky="ew")
        options_frame.columnconfigure(0, weight=1)
        options_frame.columnconfigure(0, weight=1)
        options_frame.columnconfigure(1, weight=1)
        
        # Withdraw button
        withdraw_button = ttk.Button(
            options_frame,
            text="Withdraw",
            command=lambda: self.controller.show_frame("WithdrawPage"),
            style="Action.TButton"
        )
        withdraw_button.grid(row=0, column=0, pady=10, padx=10, ipady=10, ipadx=20, sticky="ew")
        
        # Deposit button
        deposit_button = ttk.Button(
            options_frame,
            text="Deposit",
            command=lambda: self.controller.show_frame("DepositPage"),
            style="Action.TButton"
        )
        deposit_button.grid(row=0, column=1, pady=10, padx=10, ipady=10, ipadx=20, sticky="ew")
        
        # View transactions button
        transactions_button = ttk.Button(
            options_frame,
            text="Transaction History",
            command=lambda: self.controller.show_frame("TransactionHistoryPage"),
            style="Secondary.TButton"
        )
        transactions_button.grid(row=1, column=0, columnspan=2, pady=10, ipady=5, sticky="ew")
        
        # Logout button
        logout_button = ttk.Button(
            options_frame,
            text="Logout",
            command=self.logout,
            style="Warning.TButton"
        )
        logout_button.grid(row=2, column=0, columnspan=2, pady=(20, 10), ipady=5, sticky="ew")
        
        # Session timer
        self.timer_var = tk.StringVar()
        timer_label = ttk.Label(
            self.account_frame,
            textvariable=self.timer_var,
            style="Small.TLabel"
        )
        timer_label.grid(row=3, column=0, pady=(20, 0), sticky="e")
        
        # Session timeout in seconds
        self.session_timeout = CONFIG["session_timeout"]
        self.time_remaining = self.session_timeout
        self.timer_active = False
    
    def update_account_info(self):
        """Update account information display."""
        if not self.controller.current_user:
            return
        
        # Get user details
        user = self.controller.db.get_user_by_username(self.controller.current_user)
        if not user:
            return
        
        # Get account details
        account = self.controller.db.get_account_by_user_id(user["id"])
        if not account:
            return
        
        # Update welcome message
        self.welcome_var.set(f"Welcome, {self.controller.current_user}")
        
        # Update balance
        self.balance_var.set(f"${account['balance']:.2f}")
        
        # Start session timer
        self.start_timer()
    
    def start_timer(self):
        """Start the session timeout timer."""
        if self.timer_active:
            return
            
        self.timer_active = True
        self.time_remaining = self.session_timeout
        self.update_timer()
    
    def update_timer(self):
        """Update the session timeout timer."""
        if not self.timer_active:
            return
            
        if self.time_remaining <= 0:
            self.timer_var.set("Session expired")
            self.logout()
            return
            
        minutes = self.time_remaining // 60
        seconds = self.time_remaining % 60
        self.timer_var.set(f"Session expires in: {minutes:02d}:{seconds:02d}")
        
        self.time_remaining -= 1
        self.after(1000, self.update_timer)
    
    def reset_timer(self):
        """Reset the session timeout timer."""
        self.time_remaining = self.session_timeout
    
    def logout(self):
        """Log out the current user."""
        if self.controller.current_user:
            logger.info(f"User logged out: {self.controller.current_user}")
            
            # Log the logout event
            self.controller.db.log_security_event(
                self.controller.current_user, "logout", "success"
            )
            
            # Clear current user
            self.controller.set_current_user(None)
            
        # Stop timer
        self.timer_active = False
        
        # Return to welcome page
        self.controller.show_frame("WelcomePage")


class TransactionPage(ATMFrame):
    """Base class for transaction pages (withdraw/deposit)."""
    
    def __init__(self, parent, controller, transaction_type):
        super().__init__(parent, controller)
        self.transaction_type = transaction_type
        self.set_header(f"{transaction_type.capitalize()} Funds")

        self.grid_rowconfigure(0, weight=1)  # Allow rows to expand
        self.grid_columnconfigure(0, weight=1)  # Allow columns to expand

        
        # Transaction form
        form_frame = ttk.Frame(self.content_frame, style="Content.TFrame")
        form_frame.grid(row=1, column=0, pady=20, sticky="nsew")
        form_frame.columnconfigure(1, weight=1)
        
        # Current balance display
        balance_label = ttk.Label(
            form_frame,
            text="Current Balance:",
            style="Label.TLabel"
        )
        balance_label.grid(row=0, column=0, pady=10, sticky="w")
        
        self.balance_var = tk.StringVar()
        balance_amount = ttk.Label(
            form_frame,
            textvariable=self.balance_var,
            style="Balance.TLabel"
        )
        balance_amount.grid(row=0, column=1, padx=10, sticky="e")
        
        # Amount field
        amount_label = ttk.Label(
            form_frame,
            text="Amount:",
            style="Label.TLabel"
        )
        amount_label.grid(row=1, column=0, pady=10, sticky="w")
        
        self.amount_var = tk.StringVar()
        amount_entry = ttk.Entry(
            form_frame,
            textvariable=self.amount_var,
            width=20
        )
        amount_entry.grid(row=1, column=1, pady=10, sticky="e")
        
        # Quick amount buttons
        quick_frame = ttk.Frame(form_frame, style="Content.TFrame")
        quick_frame.grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")
        
        # Add quick amount buttons
        amounts = [20, 50, 100, 200]
        for i, amount in enumerate(amounts):
            quick_button = ttk.Button(
                quick_frame,
                text=f"${amount}",
                command=lambda a=amount: self.set_amount(a),
                style="Quick.TButton"
            )
            quick_button.grid(row=0, column=i, padx=5, pady=5, sticky="ew")
            quick_frame.columnconfigure(i, weight=1)
        
        # Transaction button
        self.transaction_button = ttk.Button(
            form_frame,
            text=f"{transaction_type.capitalize()}",
            command=self.process_transaction,
            style="Primary.TButton"
        )
        self.transaction_button.grid(row=3, column=0, columnspan=2, pady=20, ipady=5)
        
        # Status message
        self.status_var = tk.StringVar()
        status_label = ttk.Label(
            form_frame,
            textvariable=self.status_var,
            style="Status.TLabel"
        )
        status_label.grid(row=4, column=0, columnspan=2, pady=10)
        
        # Back button
        back_button = ttk.Button(
            form_frame,
            text="Back",
            command=lambda: self.controller.show_frame("AccountPage"),
            style="Secondary.TButton"
        )
        back_button.grid(row=5, column=0, columnspan=2, pady=10)
    
    def set_amount(self, amount):
        """Set the amount field to a predetermined value."""
        self.amount_var.set(str(amount))
    
    def update_balance(self):
        """Update the balance display."""
        if not self.controller.current_user:
            return
            
        # Get user details
        user = self.controller.db.get_user_by_username(self.controller.current_user)
        if not user:
            return
            
        # Get account details
        account = self.controller.db.get_account_by_user_id(user["id"])
        if not account:
            return
            
        # Update balance display
        self.balance_var.set(f"${account['balance']:.2f}")
        
        # Reset other fields
        self.amount_var.set("")
        self.status_var.set("")
    
    def process_transaction(self):
        """Process the transaction - to be implemented by subclasses."""
        pass
    
    def clear_fields(self):
        """Clear input fields."""
        self.amount_var.set("")
        self.status_var.set("")


class WithdrawPage(TransactionPage):
    """Page for withdrawing funds."""
    
    def __init__(self, parent, controller):
        super().__init__(parent, controller, "withdraw")
        self.grid_rowconfigure(0, weight=1)  # Allow rows to expand
        self.grid_columnconfigure(0, weight=1)  # Allow columns to expand

    
    def process_transaction(self):
        """Process a withdrawal transaction."""
        if not self.controller.current_user:
            self.status_var.set("No active session. Please log in again.")
            return
            
        try:
            amount = float(self.amount_var.get())
        except ValueError:
            self.status_var.set("Please enter a valid amount.")
            return
            
        # Validate amount
        if amount <= 0:
            self.status_var.set("Amount must be greater than zero.")
            return
            
        if amount > CONFIG["max_withdrawal"]:
            self.status_var.set(f"Maximum withdrawal amount is ${CONFIG['max_withdrawal']}.")
            return
            
        # Get user and account
        user = self.controller.db.get_user_by_username(self.controller.current_user)
        account = self.controller.db.get_account_by_user_id(user["id"])
        
        # Check if sufficient funds
        if amount > account["balance"]:
            self.status_var.set("Insufficient funds.")
            return
            
        # Update balance
        new_balance = account["balance"] - amount
        if self.controller.db.update_balance(account["id"], new_balance):
            # Record transaction
            self.controller.db.record_transaction(
                account["id"], "withdrawal", amount, new_balance,
                f"ATM withdrawal by {self.controller.current_user}"
            )
            
            # Show success message
            self.status_var.set(f"Successfully withdrew ${amount:.2f}")
            
            # Update balance display
            self.balance_var.set(f"${new_balance:.2f}")
            
            # Reset amount field
            self.amount_var.set("")
            
            # Reset session timer
            if hasattr(self.controller.frames["AccountPage"], "reset_timer"):
                self.controller.frames["AccountPage"].reset_timer()
        else:
            self.status_var.set("Transaction failed. Please try again.")


class DepositPage(TransactionPage):
    """Page for depositing funds."""
    
    def __init__(self, parent, controller):
        super().__init__(parent, controller, "deposit")
        self.grid_rowconfigure(0, weight=1)  # Allow rows to expand
        self.grid_columnconfigure(0, weight=1)  # Allow columns to expand

    
    def process_transaction(self):
        """Process a deposit transaction."""
        if not self.controller.current_user:
            self.status_var.set("No active session. Please log in again.")
            return
            
        try:
            amount = float(self.amount_var.get())
        except ValueError:
            self.status_var.set("Please enter a valid amount.")
            return
            
        # Validate amount
        if amount <= 0:
            self.status_var.set("Amount must be greater than zero.")
            return
            
        if amount < CONFIG["min_deposit"]:
            self.status_var.set(f"Minimum deposit amount is ${CONFIG['min_deposit']}.")
            return
            
        # Get user and account
        user = self.controller.db.get_user_by_username(self.controller.current_user)
        account = self.controller.db.get_account_by_user_id(user["id"])
        
        # Update balance
        new_balance = account["balance"] + amount
        if self.controller.db.update_balance(account["id"], new_balance):
            # Record transaction
            self.controller.db.record_transaction(
                account["id"], "deposit", amount, new_balance,
                f"ATM deposit by {self.controller.current_user}"
            )
            
            # Show success message
            self.status_var.set(f"Successfully deposited ${amount:.2f}")
            
            # Update balance display
            self.balance_var.set(f"${new_balance:.2f}")
            
            # Reset amount field
            self.amount_var.set("")
            
            # Reset session timer
            if hasattr(self.controller.frames["AccountPage"], "reset_timer"):
                self.controller.frames["AccountPage"].reset_timer()
        else:
            self.status_var.set("Transaction failed. Please try again.")


class TransactionHistoryPage(ATMFrame):
    """Page for displaying transaction history."""
    
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.set_header("Transaction History")
        self.grid_rowconfigure(0, weight=1)  # Allow rows to expand
        self.grid_columnconfigure(0, weight=1)  # Allow columns to expand

        
        # Transaction history container
        self.history_frame = ttk.Frame(self.content_frame, style="Content.TFrame")
        self.history_frame.grid(row=1, column=0, pady=10, sticky="nsew")
        
        # Back to account button
        back_button = ttk.Button(
            self.footer_frame,
            text="Back to Account",
            command=lambda: self.controller.show_frame("AccountPage"),
            style="Secondary.TButton"
        )
        back_button.pack(side="left", padx=5, before=self.home_button)
    
    def load_transactions(self):
        """Load and display transaction history."""
        # Clear existing widgets
        for widget in self.history_frame.winfo_children():
            widget.destroy()
            
        if not self.controller.current_user:
            return
            
        # Get user details
        user = self.controller.db.get_user_by_username(self.controller.current_user)
        if not user:
            return
            
        # Get account details
        account = self.controller.db.get_account_by_user_id(user["id"])
        if not account:
            return
            
        # Get recent transactions
        transactions = self.controller.db.get_recent_transactions(account["id"], 10)
        
        if not transactions:
            no_trans_label = ttk.Label(
                self.history_frame,
                text="No transactions found",
                style="Label.TLabel"
            )
            no_trans_label.grid(row=0, column=0, pady=20)
            return
            
        # Create headers
        headers = ["Date", "Type", "Amount", "Balance"]
        for i, header in enumerate(headers):
            header_label = ttk.Label(
                self.history_frame,
                text=header,
                style="TableHeader.TLabel"
            )
            header_label.grid(row=0, column=i, padx=5, pady=(0, 10), sticky="w")
            
        for row_idx, transaction in enumerate(transactions, start=1):
            # Date
            date_str = datetime.datetime.strptime(
                transaction["timestamp"], "%Y-%m-%d %H:%M:%S"
            ).strftime("%m/%d/%Y %H:%M")
            
            date_label = ttk.Label(
                self.history_frame,
                text=date_str,
                style="TableCell.TLabel"
            )
            date_label.grid(row=row_idx, column=0, padx=5, pady=2, sticky="w")
            
            # Type (capitalize first letter)
            transaction_type = transaction["transaction_type"].capitalize()
            type_label = ttk.Label(
                self.history_frame,
                text=transaction_type,
                style="TableCell.TLabel"
            )
            type_label.grid(row=row_idx, column=1, padx=5, pady=2, sticky="w")
            
            # Amount (with + or - prefix)
            amount = transaction["amount"]
            if transaction["transaction_type"] == "withdrawal":
                amount_str = f"-${amount:.2f}"
                amount_style = "TableCellNegative.TLabel"
            else:
                amount_str = f"+${amount:.2f}"
                amount_style = "TableCellPositive.TLabel"
                
            amount_label = ttk.Label(
                self.history_frame,
                text=amount_str,
                style=amount_style
            )
            amount_label.grid(row=row_idx, column=2, padx=5, pady=2, sticky="w")
            
            # Balance
            balance_label = ttk.Label(
                self.history_frame,
                text=f"${transaction['balance_after']:.2f}",
                style="TableCell.TLabel"
            )
            balance_label.grid(row=row_idx, column=3, padx=5, pady=2, sticky="w")
            
        # Add a separator between rows
        for row_idx in range(1, len(transactions) + 1):
            ttk.Separator(self.history_frame, orient="horizontal").grid(
                row=row_idx + 1, column=0, columnspan=4, sticky="ew", pady=2
            )
        
        # Reset session timer on account page
        if hasattr(self.controller.frames["AccountPage"], "reset_timer"):
            self.controller.frames["AccountPage"].reset_timer()


class ATMApplication(tk.Tk):
    """Main application class."""
    
    def __init__(self):
        super().__init__()

        
        # Initialize application properties
        self.attributes('-fullscreen', True)  # Start in full-screen mode
        self.bind("<Escape>", lambda e: self.attributes('-fullscreen', False))  # Press Escape to exit full-screen
        self.bind("<F1>", lambda e: self.toggle_fullscreen())  # Press F1 to toggle full-screen


        self.title(APP_TITLE)
        self.geometry("720x600")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Set application icon (would use a real icon in production)
        # self.iconbitmap("path/to/icon.ico")
        
        # Initialize database and facial recognition
        try:
            self.db = Database(DB_PATH)
            self.face_system = FacialRecognition(FACE_DATA_DIR)
        except Exception as e:
            logger.critical(f"Fatal error initializing system: {e}")
            messagebox.showerror("System Error", "Failed to initialize system. Check logs for details.")
            self.destroy()
            return
        
        # Current user
        self.current_user = None
        
        # Configure styles
        self.configure_styles()
        
        # Create main container
        container = ttk.Frame(self)
        container.pack(side="top", fill="both", expand=True)

        # Configure grid expansion
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        
        # Initialize frames dictionary
        self.frames = {}
        
        # Create all frames
        frame_classes = {
            "WelcomePage": WelcomePage,
            "RegistrationPage": RegistrationPage,
            "LoginPage": LoginPage,
            "AccountPage": AccountPage,
            "WithdrawPage": WithdrawPage,
            "DepositPage": DepositPage,
            "TransactionHistoryPage": TransactionHistoryPage
        }
        
        for name, frame_class in frame_classes.items():
            frame = frame_class(container, self)
            self.frames[name] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        
        # Show welcome page initially
        self.show_frame("WelcomePage")


    def toggle_fullscreen(self):
        """Toggle full-screen mode on/off."""
        is_fullscreen = self.attributes('-fullscreen')
        self.attributes('-fullscreen', not is_fullscreen)

    
    def configure_styles(self):
        """Configure ttk styles for the application."""
        style = ttk.Style()
        
        # Configure theme
        style.theme_use("clam")  # Use a modern-looking theme
        
        # Frame styles
        style.configure("ATM.TFrame", background=THEME["background"])
        style.configure("Content.TFrame", background=THEME["background"])
        style.configure("Footer.TFrame", background=THEME["background"])
        style.configure("Card.TFrame", background=THEME["background"], relief="raised")
        
        # Label styles
        style.configure("Header.TLabel", 
                       font=("Arial", 24, "bold"),
                       foreground=THEME["primary_dark"],
                       background=THEME["background"])
        
        style.configure("SubHeader.TLabel", 
                       font=("Arial", 18),
                       foreground=THEME["primary"],
                       background=THEME["background"])
        
        style.configure("Label.TLabel", 
                       font=("Arial", 12),
                       foreground=THEME["text_dark"],
                       background=THEME["background"])
        
        style.configure("Status.TLabel", 
                       font=("Arial", 12, "italic"),
                       foreground=THEME["primary"],
                       background=THEME["background"])
        
        style.configure("Balance.TLabel", 
                       font=("Arial", 16, "bold"),
                       foreground=THEME["text_dark"],
                       background=THEME["background"])
        
        style.configure("Small.TLabel", 
                       font=("Arial", 10),
                       foreground=THEME["text_dark"],
                       background=THEME["background"])
        
        style.configure("Instruction.TLabel", 
                       font=("Arial", 12),
                       foreground=THEME["text_dark"],
                       background=THEME["background"],
                       justify="center")
        
        # Table styles
        style.configure("TableHeader.TLabel", 
                       font=("Arial", 12, "bold"),
                       foreground=THEME["primary_dark"],
                       background=THEME["background"])
        
        style.configure("TableCell.TLabel", 
                       font=("Arial", 12),
                       foreground=THEME["text_dark"],
                       background=THEME["background"])
        
        style.configure("TableCellPositive.TLabel", 
                       font=("Arial", 12),
                       foreground=THEME["success"],
                       background=THEME["background"])
        
        style.configure("TableCellNegative.TLabel", 
                       font=("Arial", 12),
                       foreground=THEME["error"],
                       background=THEME["background"])
        
        # Button styles
        style.configure("TButton", 
                       font=("Arial", 12),
                       background=THEME["primary"])
        
        style.configure("Primary.TButton", 
                       font=("Arial", 14, "bold"),
                       background=THEME["primary"])
        
        style.configure("Secondary.TButton", 
                       font=("Arial", 12),
                       background=THEME["background"])
        
        style.configure("Action.TButton", 
                       font=("Arial", 14),
                       background=THEME["accent"])
        
        style.configure("Warning.TButton", 
                       font=("Arial", 12),
                       background=THEME["warning"])
        
        style.configure("Danger.TButton", 
                       font=("Arial", 12),
                       background=THEME["error"])
        
        style.configure("Navigation.TButton", 
                       font=("Arial", 12),
                       background=THEME["primary_dark"])
        
        style.configure("Quick.TButton", 
                       font=("Arial", 12),
                       background=THEME["background"])
    
    def show_frame(self, frame_name):
        """Show the specified frame and update its content if needed."""
        frame = self.frames[frame_name]
        
        # Special handling for different frame types
        if frame_name == "AccountPage" and self.current_user:
            frame.update_account_info()
        elif frame_name == "WithdrawPage" or frame_name == "DepositPage":
            frame.update_balance()
        elif frame_name == "TransactionHistoryPage" and self.current_user:
            frame.load_transactions()
        
        # Raise frame to top
        frame.tkraise()
    
    def set_current_user(self, username):
        """Set the current user."""
        self.current_user = username
    
    def on_closing(self):
        """Handle window closing event."""
        if messagebox.askokcancel("Quit", "Are you sure you want to quit?"):
            logger.info("Application closing")
            
            # Log out current user if any
            if self.current_user:
                self.db.log_security_event(
                    self.current_user, "logout", "success", details="Application closed"
                )
            
            self.destroy()


def initialize_database():
    """Initialize the database with test data if needed."""
    db = Database(DB_PATH)
    
    # Check if users table is empty
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as count FROM users")
    result = cursor.fetchone()
    
    if result["count"] == 0:
        logger.info("Creating test user")
        
        # Create test face data directory
        test_user = "demo_user"
        user_data_path = os.path.join(FACE_DATA_DIR, test_user)
        os.makedirs(user_data_path, exist_ok=True)
        
        # Create dummy face data file
        with open(os.path.join(user_data_path, "metadata.txt"), "w") as f:
            f.write(f"username: {test_user}\n")
            f.write(f"created: {datetime.datetime.now().isoformat()}\n")
            f.write(f"faces_captured: 1\n")
        
        # Register user
        db.create_user(test_user, user_data_path)
        
        # Get user and account
        user = db.get_user_by_username(test_user)
        account = db.get_account_by_user_id(user["id"])
        
        # Add initial balance
        db.update_balance(account["id"], 1000.0)
        
        # Add sample transactions
        db.record_transaction(account["id"], "deposit", 1000.0, 1000.0, "Initial deposit")
        
        logger.info("Test data created")
    
    conn.close()


def main():
    """Main entry point for the application."""
    try:
        # Set up logging
        logger.info("Starting ATM Application")
        
        # Initialize database with test data if needed
        initialize_database()
        
        # Create and run application
        app = ATMApplication()
        app.mainloop()
        
    except Exception as e:
        logger.critical(f"Unhandled exception: {e}", exc_info=True)
        messagebox.showerror("Critical Error", "An unrecoverable error occurred. The application will exit.")


if __name__ == "__main__":
    main()
