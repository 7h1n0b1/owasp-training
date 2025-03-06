const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const { adminCredentials, systemConfig } = require('./config');

const app = express();
const PORT = process.env.PORT || 3000;
const USER_DATA_FILE = path.join(__dirname, 'users.json');
const STATS_DATA_FILE = path.join(__dirname, 'stats.json');

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '..')));

// Initialize data files if they don't exist
if (!fs.existsSync(USER_DATA_FILE)) {
  fs.writeFileSync(USER_DATA_FILE, JSON.stringify([], null, 2));
  console.log('Created users.json file');
}

if (!fs.existsSync(STATS_DATA_FILE)) {
  fs.writeFileSync(STATS_DATA_FILE, JSON.stringify({}, null, 2));
  console.log('Created stats.json file');
}

// Route to save user data
app.post('/save-user', (req, res) => {
  try {
    const userData = req.body;
    
    // Basic validation
    if (!userData || !userData.username || !userData.password) {
      return res.status(400).json({ error: 'Invalid user data' });
    }
    
    // Load existing users
    let users = [];
    if (fs.existsSync(USER_DATA_FILE)) {
      const fileData = fs.readFileSync(USER_DATA_FILE, 'utf8');
      users = JSON.parse(fileData);
    }
    
    // Check if user already exists
    const existingUser = users.find(user => user.username === userData.username);
    if (existingUser) {
      return res.status(409).json({ error: 'Username already exists' });
    }
    
    // Add new user
    users.push(userData);
    
    // Save updated users list
    fs.writeFileSync(USER_DATA_FILE, JSON.stringify(users, null, 2));
    
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error saving user data:', error);
    res.status(500).json({ error: 'Failed to save user data' });
  }
});

// Route to reset password
app.post('/reset-password', (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Basic validation
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    // Load existing users
    let users = [];
    if (fs.existsSync(USER_DATA_FILE)) {
      const fileData = fs.readFileSync(USER_DATA_FILE, 'utf8');
      users = JSON.parse(fileData);
    }
    
    // Find the user
    const userIndex = users.findIndex(user => user.username === username);
    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Update the password
    users[userIndex].password = password;
    
    // Save updated users list
    fs.writeFileSync(USER_DATA_FILE, JSON.stringify(users, null, 2));
    
    res.status(200).json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// Secure route to get users data (without passwords)
app.get('/get-users', (req, res) => {
  try {
    // Load existing users
    let users = [];
    if (fs.existsSync(USER_DATA_FILE)) {
      const fileData = fs.readFileSync(USER_DATA_FILE, 'utf8');
      const fullUsers = JSON.parse(fileData);
      
      // Strip sensitive data
      users = fullUsers.map(user => {
        const { password, securityAnswer, ...safeUser } = user;
        return safeUser;
      });
    }
    
    res.status(200).json(users);
  } catch (error) {
    console.error('Error loading users:', error);
    res.status(500).json({ error: 'Failed to load users' });
  }
});

// Authentication endpoint for login
app.post('/auth', (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Check if admin login
    if (username === adminCredentials.username && password === adminCredentials.password) {
      return res.status(200).json({
        success: true,
        user: {
          username: adminCredentials.username,
          isAdmin: true
        }
      });
    }
    
    // Check if registered user
    let users = [];
    if (fs.existsSync(USER_DATA_FILE)) {
      const fileData = fs.readFileSync(USER_DATA_FILE, 'utf8');
      users = JSON.parse(fileData);
    }
    
    const user = users.find(u => u.username === username && u.password === password);
    
    if (user) {
      // Don't send the password back to the client
      const { password, securityAnswer, ...userWithoutSensitiveData } = user;
      
      return res.status(200).json({
        success: true,
        user: {
          ...userWithoutSensitiveData,
          isAdmin: false
        }
      });
    }
    
    // No user found
    return res.status(401).json({
      success: false,
      message: 'Invalid username or password'
    });
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
});

// Stats management endpoints
app.get('/stats', (req, res) => {
  try {
    if (!fs.existsSync(STATS_DATA_FILE)) {
      return res.status(200).json({});
    }
    
    const statsData = fs.readFileSync(STATS_DATA_FILE, 'utf8');
    const stats = JSON.parse(statsData);
    
    res.status(200).json(stats);
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

app.post('/stats', (req, res) => {
  try {
    const statsData = req.body;
    fs.writeFileSync(STATS_DATA_FILE, JSON.stringify(statsData, null, 2));
    
    res.status(200).json({ message: 'Statistics updated successfully' });
  } catch (error) {
    console.error('Error updating stats:', error);
    res.status(500).json({ error: 'Failed to update statistics' });
  }
});

app.post('/track-attempt', (req, res) => {
  try {
    const { username, challengeId, isCorrect } = req.body;
    
    if (!username || !challengeId || isCorrect === undefined) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    let stats = {};
    if (fs.existsSync(STATS_DATA_FILE)) {
      const statsData = fs.readFileSync(STATS_DATA_FILE, 'utf8');
      stats = JSON.parse(statsData);
    }
    
    // Initialize user stats if they don't exist
    if (!stats[username]) {
      stats[username] = {
        challenges: {},
        totalAttempts: 0,
        totalCorrect: 0,
        accuracyPercentage: 0
      };
    }
    
    const userStats = stats[username];
    
    // Initialize challenge stats if they don't exist
    if (!userStats.challenges[challengeId]) {
      userStats.challenges[challengeId] = {
        attempts: 0,
        correct: 0,
        solved: false,
        lastAttempt: null
      };
    }
    
    const challengeStats = userStats.challenges[challengeId];
    
    // Update challenge stats
    challengeStats.attempts++;
    if (isCorrect) {
      challengeStats.correct++;
      challengeStats.solved = true;
    }
    challengeStats.lastAttempt = new Date().toISOString();
    
    // Update user totals
    userStats.totalAttempts++;
    if (isCorrect) {
      userStats.totalCorrect++;
    }
    
    // Calculate new accuracy percentage
    userStats.accuracyPercentage = Math.round((userStats.totalCorrect / userStats.totalAttempts) * 100);
    
    // Save updated stats
    fs.writeFileSync(STATS_DATA_FILE, JSON.stringify(stats, null, 2));
    
    res.status(200).json({ 
      message: 'Challenge attempt recorded successfully', 
      stats: userStats 
    });
  } catch (error) {
    console.error('Error recording challenge attempt:', error);
    res.status(500).json({ error: 'Failed to record challenge attempt' });
  }
});

app.delete('/stats/:username', (req, res) => {
  try {
    const { username } = req.params;
    
    let stats = {};
    if (fs.existsSync(STATS_DATA_FILE)) {
      const statsData = fs.readFileSync(STATS_DATA_FILE, 'utf8');
      stats = JSON.parse(statsData);
    }
    
    if (!stats[username]) {
      return res.status(404).json({ error: 'User stats not found' });
    }
    
    delete stats[username];
    fs.writeFileSync(STATS_DATA_FILE, JSON.stringify(stats, null, 2));
    
    res.status(200).json({ message: `Statistics for ${username} deleted successfully` });
  } catch (error) {
    console.error('Error deleting user stats:', error);
    res.status(500).json({ error: 'Failed to delete user statistics' });
  }
});

app.delete('/stats', (req, res) => {
  try {
    fs.writeFileSync(STATS_DATA_FILE, JSON.stringify({}, null, 2));
    res.status(200).json({ message: 'All statistics cleared successfully' });
  } catch (error) {
    console.error('Error clearing stats:', error);
    res.status(500).json({ error: 'Failed to clear statistics' });
  }
});

// Admin password management
app.put('/admin/update-password', (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (currentPassword !== adminCredentials.password) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    // In a real application, we would update the config file or database
    // For this demo, we'll simulate a successful password update
    
    res.status(200).json({ message: 'Admin password updated successfully' });
  } catch (error) {
    console.error('Error updating admin password:', error);
    res.status(500).json({ error: 'Failed to update admin password' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`User data is stored in ${USER_DATA_FILE}`);
  console.log(`Stats data is stored in ${STATS_DATA_FILE}`);
});