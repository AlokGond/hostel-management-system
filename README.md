# Hostel Management System

A web-based hostel management system built with Flask that allows students to request rooms and administrators to manage room allocations.

## Features

- User Authentication (Student and Admin)
- Room Booking System
- Admin Dashboard
- Student Dashboard
- Room Request Management
- Modern and Responsive UI

## Prerequisites

- Python 3.7+
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd hostel-management
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the application:
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Default Admin Credentials

- Email: test@admin.com
- Password: Admin@123

## Project Structure

```
hostel-management/
├── app.py
├── requirements.txt
├── static/
│   └── css/
│       └── style.css
└── templates/
    ├── admin_dashboard.html
    ├── base.html
    ├── index.html
    ├── login.html
    ├── request_room.html
    ├── signup.html
    └── student_dashboard.html
```

## Making it Live

To make the application live, you can deploy it to various platforms:

### Render Deployment (Recommended)

1. **Create a Render account and service**:
   - Sign up for a Render account at https://render.com
   - Create a new Web Service
   - Connect your GitHub repository

2. **Configure your Web Service**:
   - Set the Build Command: `pip install -r requirements.txt`
   - Set the Start Command: `gunicorn app:app`
   - Select Python as the runtime
   - Choose the appropriate instance type

3. **Set up Environment Variables**:
   - `DATABASE_URL`: Your PostgreSQL connection string (Render will provide this if you use their PostgreSQL service)
   - `SECRET_KEY`: A secure random string
   - `FLASK_ENV`: Set to `production`

4. **Set up PostgreSQL database**:
   - Create a new PostgreSQL database on Render
   - Render will automatically set the DATABASE_URL environment variable
   - The app is configured to work with this automatically

5. **Troubleshooting Tips**:
   - If database tables aren't being created, run `python render_check.py` to diagnose
   - The release command in Procfile should automatically create tables
   - Default admin credentials will be created automatically:
     - Email: `admin@example.com`
     - Password: `admin123`

### Other Deployment Options

1. Heroku:
   - Create a Heroku account
   - Install Heroku CLI
   - Create a Procfile with: `web: gunicorn app:app`
   - Add `gunicorn` to requirements.txt
   - Deploy using Heroku CLI or GitHub integration

2. PythonAnywhere:
   - Create a PythonAnywhere account
   - Upload your code
   - Set up a virtual environment
   - Configure WSGI file
   - Set up your web app

3. DigitalOcean:
   - Create a droplet
   - Set up your server with nginx
   - Configure gunicorn
   - Set up SSL with Let's Encrypt

## Contributing

Feel free to submit issues and enhancement requests!
