const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const PDFDocument = require('pdfkit');
const MongoStore = require('connect-mongo');
const axios = require('axios');
const { spawn } = require('child_process');

const app = express();

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname)));
app.use(session({
    secret: 'your_secret',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: 'mongodb://localhost:27017/cyberguard',
        collectionName: 'sessions',
        ttl: 86400
    }),
    cookie: {
        secure: false,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// NewsAPI configuration
const NEWS_API_KEY = 'afb2bbcbccd448bf937510ff0caed3ae'; // Updated NewsAPI key
const NEWS_API_URL = 'https://newsapi.org/v2/everything';

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/cyberguard')
.then(() => {
    console.log('✅ Connected to MongoDB successfully');
    console.log('📊 Database: cyberguard');
    console.log('🔗 URL: mongodb://localhost:27017');
}).catch((err) => {
    console.error('❌ MongoDB connection error:');
    console.error('   Error details:', err.message);
    console.error('   Please make sure:');
    console.error('   1. MongoDB is installed and running');
    console.error('   2. MongoDB Compass is properly configured');
    console.error('   3. The connection URL is correct');
    process.exit(1);
});

// Add connection error handler
mongoose.connection.on('error', (err) => {
    console.error('MongoDB connection error:', err);
});

// Add disconnection handler
mongoose.connection.on('disconnected', () => {
    console.log('MongoDB disconnected');
});

// Add reconnection handler
mongoose.connection.on('reconnected', () => {
    console.log('MongoDB reconnected');
});

// User Model
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    scanCount: { type: Number, default: 0 },
    scanHistory: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Scan'
    }]
});

// Scan Model
const scanSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    url: {
        type: String,
        required: true
    },
    scanType: {
        type: String,
        enum: ['passive', 'active'],
        required: true
    },
    scanDate: {
        type: Date,
        default: Date.now
    },
    status: {
        type: String,
        enum: ['in-progress', 'completed', 'failed'],
        default: 'in-progress'
    },
    results: {
        totalAlerts: Number,
        criticalAlerts: Number,
        highAlerts: Number,
        mediumAlerts: Number,
        lowAlerts: Number,
        alerts: [{
            risk: String,
            name: String,
            description: String,
            solution: String,
            url: String
        }]
    },
    systemHealth: {
        score: Number,
        status: String
    },
    progress: {
        type: Number,
        default: 0
    },
    currentStage: {
        type: String,
        default: 'Initializing'
    }
});

// User Scan History Model
const userScanHistorySchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    scanHistory: [{
        url: {
            type: String,
            required: true
        },
        scanType: {
            type: String,
            enum: ['passive', 'active'],
            required: true
        },
        scanDate: {
            type: Date,
            default: Date.now
        },
        status: {
            type: String,
            enum: ['in-progress', 'completed', 'failed'],
            default: 'in-progress'
        },
        results: {
            totalAlerts: Number,
            criticalAlerts: Number,
            highAlerts: Number,
            mediumAlerts: Number,
            lowAlerts: Number,
            alerts: [{
                risk: String,
                name: String,
                description: String,
                solution: String,
                url: String
            }]
        },
        systemHealth: {
            score: Number,
            status: String
        },
        error: String
    }]
});

const User = mongoose.model('User', userSchema);
const Scan = mongoose.model('Scan', scanSchema);
const UserScanHistory = mongoose.model('UserScanHistory', userScanHistorySchema);

// Authentication Middleware
const requireAuth = (req, res, next) => {
    if (!req.session.userId) {
        return res.status(401).json({ message: 'Authentication required' });
    }
    next();
};

// Routes
app.post('/api/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already registered' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const user = new User({
            name,
            email,
            password: hashedPassword
        });
        await user.save();

        // Create user scan history collection
        const userScanHistory = new UserScanHistory({
            userId: user._id,
            scanHistory: []
        });
        await userScanHistory.save();

        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Error creating user' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Initialize new session
        req.session.regenerate(async (err) => {
            if (err) {
                console.error('Session regeneration error:', err);
                return res.status(500).json({ message: 'Error during login' });
            }

            // Set session data
            req.session.userId = user._id;
            req.session.lastScanId = null;
            req.session.metricsInitialized = false;

            // Save the session explicitly
            await new Promise((resolve, reject) => {
                req.session.save((err) => {
                    if (err) {
                        console.error('Session save error:', err);
                        reject(err);
                    } else {
                        resolve();
                    }
                });
            });

            console.log('Session initialized with data:', {
                userId: req.session.userId,
                lastScanId: req.session.lastScanId,
                metricsInitialized: req.session.metricsInitialized
            });

            res.json({ 
                message: 'Logged in successfully',
                name: user.name
            });
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Error logging in' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'Logged out successfully' });
});

// Protect the main page
app.get('/cyber.html', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'cyber.html'));
});

// Add new endpoint to get user data
app.get('/api/user', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ name: user.name });
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({ message: 'Error fetching user data' });
    }
});

// Add ZAP scanning endpoint
app.post('/api/scan', requireAuth, async (req, res) => {
    try {
        const { url, scanType } = req.body;
        const userId = req.session.userId;

        // Validate scan type
        if (!['passive', 'active'].includes(scanType)) {
            return res.status(400).json({ message: 'Invalid scan type. Must be either "passive" or "active"' });
        }

        // Create new scan record
        const scan = new Scan({
            userId,
            url,
            status: 'in-progress',
            scanType: scanType
        });
        await scan.save();

        // Increment user's scan count
        await User.findByIdAndUpdate(userId, {
            $inc: { scanCount: 1 },
            $push: { scanHistory: scan._id }
        });

        // Start ZAP scan in background with userId
        startZapScan(url, scan._id, scanType, userId);

        res.json({ 
            message: 'Scan initiated',
            scanId: scan._id
        });
    } catch (error) {
        console.error('Scan error:', error);
        res.status(500).json({ message: 'Error starting scan' });
    }
});

// Add endpoint to get scan status
app.get('/api/scan/:scanId', requireAuth, async (req, res) => {
    try {
        const scan = await Scan.findById(req.params.scanId);
        if (!scan) {
            return res.status(404).json({ message: 'Scan not found' });
        }
        if (scan.userId.toString() !== req.session.userId) {
            return res.status(403).json({ message: 'Unauthorized' });
        }
        res.json(scan);
    } catch (error) {
        console.error('Error fetching scan:', error);
        res.status(500).json({ message: 'Error fetching scan data' });
    }
});

// Add endpoint to get user's scan history
app.get('/api/scans', requireAuth, async (req, res) => {
    try {
        const scans = await Scan.find({ userId: req.session.userId })
            .sort({ scanDate: -1 });
        res.json(scans);
    } catch (error) {
        console.error('Error fetching scan history:', error);
        res.status(500).json({ message: 'Error fetching scan history' });
    }
});

// Add endpoint to get recent alerts
app.get('/api/recent-alerts', requireAuth, async (req, res) => {
    try {
        const recentScans = await Scan.find({ 
            userId: req.session.userId,
            status: 'completed',
            'results.alerts': { $exists: true, $ne: [] }
        })
        .sort({ scanDate: -1 })
        .limit(1);

        if (recentScans.length === 0) {
            return res.json({ alerts: [] });
        }

        const mostRecentScan = recentScans[0];
        
        // Sort alerts by severity (High > Medium > Low)
        const sortedAlerts = mostRecentScan.results.alerts.sort((a, b) => {
            const severityOrder = { 'High': 3, 'Medium': 2, 'Low': 1 };
            return severityOrder[b.risk] - severityOrder[a.risk];
        });

        // Take only the first 5 alerts
        const limitedAlerts = sortedAlerts.slice(0, 5);

        res.json({ 
            alerts: limitedAlerts,
            scanDate: mostRecentScan.scanDate,
            url: mostRecentScan.url,
            hasMoreAlerts: sortedAlerts.length > 5,
            scanId: mostRecentScan._id
        });
    } catch (error) {
        console.error('Error fetching recent alerts:', error);
        res.status(500).json({ message: 'Error fetching recent alerts' });
    }
});

// Add new endpoint to get scan progress
app.get('/api/scan-progress/:scanId', requireAuth, async (req, res) => {
    try {
        const scan = await Scan.findById(req.params.scanId);
        if (!scan) {
            return res.status(404).json({ message: 'Scan not found' });
        }
        if (scan.userId.toString() !== req.session.userId) {
            return res.status(403).json({ message: 'Unauthorized' });
        }
        res.json({ 
            status: scan.status,
            progress: scan.progress || 0,
            stage: scan.currentStage || 'Initializing'
        });
    } catch (error) {
        console.error('Error fetching scan progress:', error);
        res.status(500).json({ message: 'Error fetching scan progress' });
    }
});

// ZAP scanning function
async function startZapScan(targetUrl, scanId, scanType, userId) {
    const ZAPClient = require('zaproxy');

    async function updateProgress(progress, stage) {
        await Scan.findByIdAndUpdate(scanId, {
            progress: progress,
            currentStage: stage
        });
    }

    try {
        console.log('Initializing ZAP scan for:', targetUrl);
        await updateProgress(5, 'Initializing ZAP');
        
        // Initialize ZAP API client with IPv4 configuration
        const zaproxy = new ZAPClient({
            apiKey: '37qb6vhqp8cjsickeh2larek4j',
            proxy: {
                host: '127.0.0.1',
                port: 8080
            }
        });

        // Configure ZAP before scanning
        console.log('[+] Configuring ZAP...');
        await updateProgress(10, 'Configuring ZAP');
        try {
            // First, check if ZAP is running with more detailed error handling
            try {
                const version = await zaproxy.core.version();
                console.log('[+] Successfully connected to ZAP version:', version);
            } catch (error) {
                console.error('Failed to connect to ZAP:', error.message);
                throw new Error('Unable to connect to ZAP. Please ensure ZAP is running on 127.0.0.1:8080 and properly configured.');
            }

            // Set mode to standard using the correct parameter format
            console.log('[+] Setting ZAP mode...');
            try {
                await zaproxy.core.setMode({
                    mode: 'standard'
                });
                console.log('[+] ZAP mode set to standard');
            } catch (error) {
                console.error('Error setting ZAP mode:', error.message);
                // Continue even if mode setting fails
                console.log('[+] Continuing with default mode');
            }
            
            // Create new session with proper parameters
            console.log('[+] Creating new session...');
            try {
                await zaproxy.core.newSession({
                    name: 'temp-session',
                    overwrite: true
                });
                console.log('[+] New session created');
            } catch (error) {
                console.error('Error creating new session:', error.message);
                // Continue even if session creation fails
                console.log('[+] Continuing with existing session');
            }

            // Skip context setup as it's not necessary for basic scanning
            console.log('[+] Skipping context setup...');
            await updateProgress(20, 'Configuration complete');

            // Start spider scan directly without trying to access URL first
            console.log('[+] Starting spider...');
            await updateProgress(25, 'Starting spider scan');
            try {
                const spiderResult = await zaproxy.spider.scan({
                    url: targetUrl,
                    maxChildren: 50,
                    recurse: true
                });
                const spiderId = spiderResult.scan;
                console.log('[+] Spider scan initiated with ID:', spiderId);

                // Monitor spider progress
                let lastProgress = -1;
                let stagnantCount = 0;
                while (true) {
                    const progress = await zaproxy.spider.status({
                        scanId: spiderId
                    });
                    const spiderProgress = parseInt(progress.status);
                    
                    // Check for stagnant progress
                    if (spiderProgress === lastProgress) {
                        stagnantCount++;
                        if (stagnantCount > 15) { // Break if progress is stagnant for too long
                            console.log('[+] Spider progress stagnant, moving to next phase');
                            break;
                        }
                    } else {
                        stagnantCount = 0;
                    }
                    lastProgress = spiderProgress;
                    
                    console.log(`[+] Spider progress: ${spiderProgress}%`);
                    await updateProgress(25 + (spiderProgress * 0.35), 'Spider scan in progress');
                    if (spiderProgress >= 100) break;
                    await new Promise(resolve => setTimeout(resolve, 2000));
                }
                console.log('[+] Spider completed');
                await updateProgress(60, 'Spider scan complete');

                // Wait for passive scan to complete
                console.log('[+] Waiting for passive scan to complete...');
                await new Promise(resolve => setTimeout(resolve, 5000));
                await updateProgress(65, 'Passive scan complete');
            } catch (error) {
                console.error('Spider scan error:', error.message);
                throw new Error(`Spider scan failed: ${error.message}`);
            }

            // Active scan if requested
            if (scanType === 'active') {
                console.log('[+] Starting active scan...');
                await updateProgress(65, 'Starting active scan');
                try {
                    const scanResult = await zaproxy.ascan.scan({
                        url: targetUrl,
                        recurse: true
                    });
                    const activeScanId = scanResult.scan;
                    console.log('[+] Active scan initiated with ID:', activeScanId);

                    // Monitor active scan progress
                    let lastProgress = -1;
                    let stagnantCount = 0;
                    while (true) {
                        const progress = await zaproxy.ascan.status({
                            scanId: activeScanId
                        });
                        const ascanProgress = parseInt(progress.status);
                        
                        // Check for stagnant progress
                        if (ascanProgress === lastProgress) {
                            stagnantCount++;
                            if (stagnantCount > 15) {
                                console.log('[+] Active scan progress stagnant, moving to next phase');
                                break;
                            }
                        } else {
                            stagnantCount = 0;
                        }
                        lastProgress = ascanProgress;
                        
                        console.log(`[+] Active scan progress: ${ascanProgress}%`);
                        await updateProgress(65 + (ascanProgress * 0.3), 'Active scan in progress');
                        if (ascanProgress >= 100) break;
                        await new Promise(resolve => setTimeout(resolve, 2000));
                    }
                    console.log('[+] Active scan completed');
                    await updateProgress(95, 'Active scan complete');
                } catch (error) {
                    console.error('Active scan error:', error);
                    throw new Error(`Active scan failed: ${error.message}`);
                }
            }

            // Get alerts
            console.log('[+] Retrieving alerts...');
            await updateProgress(98, 'Retrieving alerts');
            let alerts;
            try {
                const alertsResult = await zaproxy.core.alerts({
                    baseurl: targetUrl
                });
                alerts = alertsResult.alerts || [];
                
                if (alerts && alerts.length > 0) {
                    console.log(`[+] Found ${alerts.length} vulnerabilities:`);
                    alerts.slice(0, 5).forEach(alert => {
                        console.log(`[!] ${alert.risk} - ${alert.name}: ${alert.url}`);
                    });
                } else {
                    console.log('[+] No vulnerabilities found.');
                }

                // Process alerts and update database
                const results = {
                    totalAlerts: alerts.length,
                    criticalAlerts: 0,
                    highAlerts: 0,
                    mediumAlerts: 0,
                    lowAlerts: 0,
                    alerts: alerts.map(alert => ({
                        risk: alert.risk,
                        name: alert.name,
                        description: alert.description || '',
                        solution: alert.solution || '',
                        url: alert.url
                    }))
                };

                // First update scan with initial results
                await Scan.findByIdAndUpdate(
                    scanId,
                    {
                        status: 'processing',
                        progress: 99,
                        currentStage: 'Processing alerts',
                        results: results,
                        scanDate: new Date()
                    }
                );

                // Process all alerts to count by severity
                console.log('[+] Processing alerts by severity...');
                for (const alert of alerts) {
                    switch (alert.risk.toLowerCase()) {
                        case 'critical':
                            results.criticalAlerts++;
                            break;
                        case 'high':
                            results.highAlerts++;
                            break;
                        case 'medium':
                            results.mediumAlerts++;
                            break;
                        case 'low':
                            results.lowAlerts++;
                            break;
                    }
                }

                // Calculate final system health after all alerts are processed
                const totalIssues = results.criticalAlerts * 5 + 
                                  results.highAlerts * 3 + 
                                  results.mediumAlerts * 2 + 
                                  results.lowAlerts;
                
                const maxScore = 100;
                const deduction = Math.min(maxScore, totalIssues * 2);
                const healthScore = Math.max(0, maxScore - deduction);

                const systemHealth = {
                    score: healthScore,
                    status: healthScore > 90 ? 'Optimal' : 
                            healthScore > 70 ? 'Good' : 
                            healthScore > 50 ? 'Fair' : 'Critical'
                };

                console.log('[+] Final scan results:', {
                    totalAlerts: results.totalAlerts,
                    criticalAlerts: results.criticalAlerts,
                    highAlerts: results.highAlerts,
                    mediumAlerts: results.mediumAlerts,
                    lowAlerts: results.lowAlerts,
                    systemHealth: systemHealth
                });

                // Final update with complete results
                const updatedScan = await Scan.findByIdAndUpdate(
                    scanId,
                    {
                        status: 'completed',
                        progress: 100,
                        currentStage: 'Scan completed',
                        results: results,
                        systemHealth: systemHealth,
                        scanDate: new Date()
                    },
                    { new: true }
                );

                // Update session metrics only after everything is processed
                try {
                    const sessionCollection = mongoose.connection.collection('sessions');
                    const sessionDoc = await sessionCollection.findOne({
                        'session.userId': userId.toString()
                    });

                    if (sessionDoc) {
                        const sessionData = JSON.parse(sessionDoc.session);
                        sessionData.lastScanId = scanId.toString();
                        sessionData.lastScanResults = {
                            activeThreats: results.criticalAlerts + results.highAlerts + results.mediumAlerts,
                            systemHealth: systemHealth,
                            totalAlerts: results.totalAlerts
                        };

                        await sessionCollection.updateOne(
                            { _id: sessionDoc._id },
                            { 
                                $set: { 
                                    session: JSON.stringify(sessionData),
                                    lastAccess: new Date()
                                } 
                            }
                        );
                        console.log('[+] Session metrics updated successfully');
                    }
                } catch (error) {
                    console.error('Error updating session metrics:', error);
                }

            } catch (error) {
                console.error('Error getting alerts:', error);
                throw new Error(`Failed to retrieve alerts: ${error.message}`);
            }

            console.log('[+] ZAP testing completed.');
        } catch (error) {
            console.error('Error during ZAP configuration:', error.message);
            // Continue with the scan even if some configuration steps fail
            console.log('[+] Attempting to continue with scan despite configuration issues');
        }
    } catch (error) {
        console.error('Scan error:', error);
        
        // Update scan record with error status
        await Scan.findByIdAndUpdate(scanId, {
            status: 'failed',
            error: error.message,
            currentStage: 'Scan failed',
            progress: 0
        });

        throw error;
    }
}

// Add endpoint to get user's scan history
app.get('/api/user-scan-history', requireAuth, async (req, res) => {
    try {
        const userHistory = await UserScanHistory.findOne({ 
            userId: req.session.userId 
        });

        if (!userHistory) {
            return res.json({ scanHistory: [] });
        }

        // Sort scan history by date in descending order
        const sortedHistory = userHistory.scanHistory.sort((a, b) => 
            b.scanDate - a.scanDate
        );

        res.json({ scanHistory: sortedHistory });
    } catch (error) {
        console.error('Error fetching user scan history:', error);
        res.status(500).json({ message: 'Error fetching scan history' });
    }
});

// Add endpoint to get user's scan count
app.get('/api/user-scan-count', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ scanCount: user.scanCount });
    } catch (error) {
        console.error('Error fetching scan count:', error);
        res.status(500).json({ message: 'Error fetching scan count' });
    }
});

// Add endpoint to get detailed alerts
app.get('/api/detailed-alerts/:scanId', requireAuth, async (req, res) => {
    try {
        const scan = await Scan.findById(req.params.scanId);
        if (!scan) {
            return res.status(404).json({ message: 'Scan not found' });
        }
        if (scan.userId.toString() !== req.session.userId) {
            return res.status(403).json({ message: 'Unauthorized' });
        }

        // Sort alerts by severity
        const sortedAlerts = scan.results.alerts.sort((a, b) => {
            const severityOrder = { 'High': 3, 'Medium': 2, 'Low': 1 };
            return severityOrder[b.risk] - severityOrder[a.risk];
        });

        res.json({
            url: scan.url,
            scanDate: scan.scanDate,
            totalAlerts: scan.results.totalAlerts,
            alerts: sortedAlerts
        });
    } catch (error) {
        console.error('Error fetching detailed alerts:', error);
        res.status(500).json({ message: 'Error fetching detailed alerts' });
    }
});

// Add endpoint to download alerts as PDF
app.get('/api/download-alerts/:scanId', requireAuth, async (req, res) => {
    try {
        const scan = await Scan.findById(req.params.scanId);
        if (!scan) {
            return res.status(404).json({ message: 'Scan not found' });
        }
        if (scan.userId.toString() !== req.session.userId) {
            return res.status(403).json({ message: 'Unauthorized' });
        }

        // Sort alerts by severity
        const sortedAlerts = scan.results.alerts.sort((a, b) => {
            const severityOrder = { 'High': 3, 'Medium': 2, 'Low': 1, 'Informational': 0 };
            return severityOrder[b.risk] - severityOrder[a.risk];
        });

        // Create PDF document
        const doc = new PDFDocument();
        
        // Set response headers
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=security-alerts-${req.params.scanId}.pdf`);
        
        // Pipe the PDF to the response
        doc.pipe(res);

        // Add content to PDF
        doc.fontSize(20).text('Security Scan Report', { align: 'center' });
        doc.moveDown();
        
        // Add scan details
        doc.fontSize(14).text('Scan Details');
        doc.fontSize(12)
           .text(`URL: ${scan.url}`)
           .text(`Scan Date: ${new Date(scan.scanDate).toLocaleString()}`)
           .text(`Total Alerts: ${scan.results.totalAlerts}`)
           .text(`System Health Score: ${scan.systemHealth.score}%`)
           .text(`System Status: ${scan.systemHealth.status}`);
        
        doc.moveDown();
        
        // Add alerts
        doc.fontSize(14).text('Security Alerts');
        doc.moveDown();

        sortedAlerts.forEach((alert, index) => {
            doc.fontSize(12)
               .text(`${index + 1}. ${alert.name}`)
               .text(`Risk Level: ${alert.risk}`, { indent: 20 })
               .text(`Description: ${alert.description}`, { indent: 20 })
               .text(`Solution: ${alert.solution}`, { indent: 20 })
               .text(`URL: ${alert.url}`, { indent: 20 });
            doc.moveDown();
        });

        // Finalize PDF
        doc.end();

    } catch (error) {
        console.error('Error generating PDF:', error);
        res.status(500).json({ message: 'Error generating PDF' });
    }
});

// Add endpoint to get dashboard metrics
app.get('/api/dashboard-metrics', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        console.log('Fetching metrics for user:', userId);
        console.log('Current session data:', req.session);

        // Get user's total scans
        const user = await User.findById(userId);
        const totalScans = user.scanCount || 0;

        // Calculate scan change percentage from previous month
        const currentDate = new Date();
        const lastMonthDate = new Date();
        lastMonthDate.setMonth(lastMonthDate.getMonth() - 1);

        const currentMonthScans = await Scan.countDocuments({
            userId: userId,
            scanDate: { $gte: lastMonthDate }
        });

        const previousMonthDate = new Date(lastMonthDate);
        previousMonthDate.setMonth(previousMonthDate.getMonth() - 1);

        const previousMonthScans = await Scan.countDocuments({
            userId: userId,
            scanDate: { 
                $gte: previousMonthDate,
                $lt: lastMonthDate
            }
        });

        const scanChange = previousMonthScans === 0 
            ? (currentMonthScans === 0 ? '0%' : '+100%')
            : `${(((currentMonthScans - previousMonthScans) / previousMonthScans) * 100).toFixed(0)}%`;

        // Always get latest scan from database
        let metrics;
        const latestScan = await Scan.findOne({ 
            userId: userId,
            status: 'completed'
        }).sort({ scanDate: -1 });

        if (latestScan && latestScan.results) {
            metrics = {
                activeThreats: (latestScan.results.criticalAlerts || 0) + (latestScan.results.highAlerts || 0),
                systemHealth: latestScan.systemHealth || { score: 0, status: 'No Data' },
                totalAlerts: latestScan.results.totalAlerts || 0
            };
        } else {
            metrics = {
                activeThreats: 0,
                systemHealth: { score: 0, status: 'No Data' },
                totalAlerts: 0
            };
        }

        // Prepare response with metrics
        const response = {
            totalScans,
            scanChange: scanChange.startsWith('-') ? scanChange : (scanChange === '0%' ? scanChange : `+${scanChange}`),
            activeThreats: metrics.activeThreats,
            threatStatus: metrics.activeThreats > 0 ? 'Critical' : 'Safe',
            threatDetails: metrics.activeThreats > 0 ? `${metrics.activeThreats} threats require attention` : 'No active threats',
            systemHealth: {
                score: metrics.systemHealth.score,
                status: metrics.systemHealth.status,
                details: `System status: ${metrics.systemHealth.status}`
            },
            totalAlerts: metrics.totalAlerts,
            alertsDetails: metrics.totalAlerts > 0 ? 'From latest scan' : 'No alerts detected'
        };

        console.log('Sending metrics response:', response);
        res.json(response);
    } catch (error) {
        console.error('Error fetching dashboard metrics:', error);
        console.error('Error details:', error.message);
        res.status(500).json({ message: 'Error fetching dashboard metrics' });
    }
});

// Add endpoint to fetch security news
app.get('/api/security-news', requireAuth, async (req, res) => {
    try {
        const response = await axios.get(NEWS_API_URL, {
            params: {
                q: '(cybersecurity OR "cyber attacks" OR "data breach" OR "ransomware" OR "cyber threat" OR "information security" OR "network security") AND NOT (stocks OR market OR financial OR earnings)',
                language: 'en',
                sortBy: 'publishedAt',
                pageSize: 3,
                apiKey: NEWS_API_KEY,
                searchIn: 'title,description', // Only search in titles and descriptions
                domains: 'thehackernews.com,bleepingcomputer.com,securityweek.com,zdnet.com,darkreading.com,threatpost.com,cyberscoop.com,infosecurity-magazine.com'
            }
        });

        const articles = response.data.articles.map(article => ({
            title: article.title,
            description: article.description,
            imageUrl: article.urlToImage || 'https://via.placeholder.com/800x400?text=Cybersecurity+News',
            url: article.url,
            source: article.source.name,
            publishedAt: article.publishedAt
        }));

        res.json(articles);
    } catch (error) {
        console.error('Error fetching security news:', error);
        res.status(500).json({ message: 'Error fetching security news' });
    }
});

// Add Gemini Chat endpoint
app.post('/api/chat', async (req, res) => {
    const message = req.body.message;

    // Validate input
    if (!message || typeof message !== 'string' || message.trim().length === 0) {
        return res.status(400).json({ error: 'Invalid message', status: 'error' });
    }

    try {
        // Spawn Python process with environment variables
        const pythonProcess = spawn('python', ['groq_chat.py'], {
            env: { ...process.env, GROQ_API_KEY: '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' },
            stdio: ['pipe', 'pipe', 'pipe']
        });

        let outputData = '';
        let errorData = '';

        // Send input to Python process immediately
        pythonProcess.stdin.write(JSON.stringify({ message }) + '\n');
        pythonProcess.stdin.end();

        // Collect output data
        pythonProcess.stdout.on('data', (data) => {
            outputData += data.toString();
        });

        // Collect error data
        pythonProcess.stderr.on('data', (data) => {
            errorData += data.toString();
            console.error('Python Error:', data.toString());
        });

        // Set timeout for the process
        const timeout = setTimeout(() => {
            pythonProcess.kill();
            console.error('Error: Python process timed out after 30 seconds.');
            res.status(504).json({ 
                error: 'Request timed out. The AI service took too long to respond. Please try again later.', 
                status: 'error',
                suggestion: 'If this happens repeatedly, check your API quota or server load.'
            });
        }, 30000);

        // Handle process completion
        pythonProcess.on('close', (code) => {
            clearTimeout(timeout);

            if (code !== 0) {
                console.error('Python process exited with code:', code);
                console.error('Error output:', errorData);
                let userMessage = 'Failed to process your message.';
                if (errorData.includes('quota')) {
                    userMessage = 'You have exceeded your Groq API quota. Please check your Groq Console quotas and billing.';
                } else if (errorData.includes('API key')) {
                    userMessage = 'There is an issue with your Groq API key. Please verify it is correct and has access.';
                }
                return res.status(500).json({ 
                    error: userMessage, 
                    status: 'error',
                    details: errorData 
                });
            }

            try {
                // Parse and validate response
                const response = JSON.parse(outputData);
                if (response.status === 'error') {
                    let userMessage = response.error || 'An unknown error occurred.';
                    if (userMessage.includes('quota')) {
                        userMessage = 'You have exceeded your Groq API quota. Please check your Groq Console quotas and billing.';
                    } else if (userMessage.includes('API key')) {
                        userMessage = 'There is an issue with your Groq API key. Please verify it is correct and has access.';
                    }
                    return res.status(500).json({
                        error: userMessage,
                        status: 'error',
                        details: response.error
                    });
                }
                res.json(response);
            } catch (error) {
                console.error('Error parsing Python response:', error);
                res.status(500).json({ 
                    error: 'Failed to parse response from AI service.', 
                    status: 'error',
                    details: outputData 
                });
            }
        });

    } catch (error) {
        console.error('Error spawning Python process:', error);
        res.status(500).json({ 
            error: 'Failed to start chat process', 
            status: 'error' 
        });
    }
});

// Start server with hardcoded port
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 