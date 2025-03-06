// Notification System
class NotificationSystem {
    constructor() {
        this.checkInterval = 30000; // Check every 30 seconds
        this.notificationSound = new Audio('/static/sounds/notification.mp3');
        this.init();
    }

    init() {
        this.startPolling();
        this.setupEventListeners();
    }

    startPolling() {
        this.checkNotifications();
        setInterval(() => this.checkNotifications(), this.checkInterval);
    }

    async checkNotifications() {
        try {
            const response = await fetch('/api/notifications/unread');
            const data = await response.json();
            if (data.notifications && data.notifications.length > 0) {
                this.showNotifications(data.notifications);
            }
        } catch (error) {
            console.error('Error checking notifications:', error);
        }
    }

    showNotifications(notifications) {
        notifications.forEach(notification => {
            this.showToast(notification);
            if (notification.type === 'urgent') {
                this.notificationSound.play();
            }
        });
        this.updateNotificationBadge(notifications.length);
    }

    showToast(notification) {
        const toast = document.createElement('div');
        toast.className = `toast notification-toast ${notification.type}`;
        toast.innerHTML = `
            <div class="toast-header">
                <strong class="me-auto">${notification.title}</strong>
                <small>${timeago(notification.created_at)}</small>
                <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
            </div>
            <div class="toast-body">
                ${notification.message}
            </div>
        `;
        document.getElementById('notification-container').appendChild(toast);
        new bootstrap.Toast(toast).show();
    }

    updateNotificationBadge(count) {
        const badge = document.getElementById('notification-badge');
        if (badge) {
            badge.textContent = count;
            badge.style.display = count > 0 ? 'inline' : 'none';
        }
    }

    setupEventListeners() {
        document.addEventListener('click', (e) => {
            if (e.target.matches('.mark-read-btn')) {
                this.markAsRead(e.target.dataset.notificationId);
            }
        });
    }

    async markAsRead(notificationId) {
        try {
            await fetch(`/api/notifications/${notificationId}/read`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
        } catch (error) {
            console.error('Error marking notification as read:', error);
        }
    }
}

// Dark Mode Toggle
function toggleTheme() {
    const body = document.body;
    body.classList.toggle('dark-mode');
    localStorage.setItem('darkMode', body.classList.contains('dark-mode'));
}

// Room Management
class RoomManager {
    static async updateRoomStatus(roomId, status) {
        try {
            const response = await fetch(`/api/rooms/${roomId}/status`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status })
            });
            return await response.json();
        } catch (error) {
            console.error('Error updating room status:', error);
            throw error;
        }
    }

    static async scheduleClean(roomId, date) {
        try {
            const response = await fetch(`/api/rooms/${roomId}/schedule-cleaning`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ date })
            });
            return await response.json();
        } catch (error) {
            console.error('Error scheduling cleaning:', error);
            throw error;
        }
    }
}

// Mess Management
class MessManager {
    static async submitFeedback(mealId, rating, comment) {
        try {
            const response = await fetch('/api/mess/feedback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mealId, rating, comment })
            });
            return await response.json();
        } catch (error) {
            console.error('Error submitting feedback:', error);
            throw error;
        }
    }

    static async requestSpecialMeal(date, requirements) {
        try {
            const response = await fetch('/api/mess/special-request', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ date, requirements })
            });
            return await response.json();
        } catch (error) {
            console.error('Error requesting special meal:', error);
            throw error;
        }
    }
}

// Initialize components
document.addEventListener('DOMContentLoaded', () => {
    // Initialize notification system
    const notificationSystem = new NotificationSystem();

    // Initialize tooltips and popovers
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));

    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(popoverTriggerEl => new bootstrap.Popover(popoverTriggerEl));

    // Check for saved theme preference
    if (localStorage.getItem('darkMode') === 'true') {
        document.body.classList.add('dark-mode');
    }
});
