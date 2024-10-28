require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const db = require('./db');
const app = express();
app.use(express.json());

// Helper to generate random password
function generatePassword() {
    return Math.random().toString(36).slice(-8);
}

// Middleware for Authentication
const authMiddleware = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).send("Access Denied");
    jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
        if (err) return res.status(403).send("Invalid Token");
        req.user = user;
        next();
    });
};

// Route to Register (Admin-only functionality)
app.post('/register', (req, res) => {
    const { username, password, role } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);
    db.query('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', 
             [username, hashedPassword, role], 
             (err) => {
                 if (err) return res.status(500).send("Error registering user");
                 res.status(201).send("User registered successfully");
             });
});

// Route to Login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err || !results.length || !bcrypt.compareSync(password, results[0].password)) {
            return res.status(401).send("Invalid Credentials");
        }
        const token = jwt.sign({ id: results[0].id, role: results[0].role }, process.env.SECRET_KEY);
        res.json({ token });
    });
});

// Route for VM Creation
app.post('/create-vm', authMiddleware, async (req, res) => {
    if (req.user.role !== 'admin' && req.user.role !== 'user') {
        return res.status(403).send("Access Denied");
    }
    const { vmName } = req.body;
    const rootPassword = generatePassword();
    const userPassword = generatePassword();

    try {
        const response = await axios.post(
            `${process.env.PROXMOX_HOST}/api2/json/nodes/pve/qemu`,
            {
                name: vmName,
                memory: 2048,
                cpu: 1,
                disk: 10,
                passwords: { root: rootPassword, user: userPassword },
            },
            {
                auth: {
                    username: process.env.PROXMOX_USER,
                    password: process.env.PROXMOX_PASS,
                },
            }
        );

        db.query('INSERT INTO vms (user_id, vm_name, status) VALUES (?, ?, ?)', 
                 [req.user.id, vmName, 'creating'], 
                 (err) => {
                     if (err) return res.status(500).send("Error creating VM record");
                     res.json({ vmId: response.data.data.vmid, rootPassword, userPassword });
                 });
    } catch (error) {
        res.status(500).send("Error creating VM on Proxmox");
    }
});

app.listen(3000, () => console.log('Server started on port 3000'));
