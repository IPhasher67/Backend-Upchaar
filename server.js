const express = require('express');
const path = require('path');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const { UserAuthModel, AdminAuthModel, TicketModel } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// Load environment variables
require('dotenv').config();

const frontendDir = path.join(__dirname, '../Frontend');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Middleware to log client IP and accessed page
app.use((req, res, next) => {
	const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
	console.log(`Client IP: ${clientIp} accessed ${req.originalUrl}`);
	next();
});

app.use(express.static(frontendDir));

// JWT Secret (in production, use a strong secret from environment variables)
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
	const authHeader = req.headers['authorization'];
	const token = authHeader && authHeader.split(' ')[1];

	if (!token) {
		return res.status(401).json({ success: false, message: 'Access token required' });
	}

	jwt.verify(token, JWT_SECRET, (err, user) => {
		if (err) {
			return res.status(403).json({ success: false, message: 'Invalid or expired token' });
		}
		req.user = user;
		next();
	});
};


// Authentication Routes

// User Registration
app.post('/api/auth/register', [
	body('name').trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters long'),
	body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email'),
	body('phone').matches(/^[\+]?[1-9][\d]{0,15}$/).withMessage('Please provide a valid phone number'),
	body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
], async (req, res) => {
	try {
		// Check for validation errors
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({
				success: false,
				message: 'Validation failed',
				errors: errors.array()
			});
		}

		const { name, email, phone, password } = req.body;

		// Check if user already exists
		const existingUser = await UserAuthModel.findOne({
			$or: [{ email }, { phone }]
		});

		if (existingUser) {
			return res.status(400).json({
				success: false,
				message: existingUser.email === email ? 'Email already registered' : 'Phone number already registered'
			});
		}

		// Create new user
		const user = new UserAuthModel({
			name,
			email,
			phone,
			password
		});

		await user.save();

		// Generate JWT token
		const token = jwt.sign(
			{ userId: user._id, email: user.email },
			JWT_SECRET,
			{ expiresIn: '1d' }
		);

		res.status(201).json({
			success: true,
			message: 'User registered successfully',
			token,
			user: {
				id: user._id,
				name: user.name,
				email: user.email,
				phone: user.phone,
				createdAt: user.createdAt
			}
		});

	} catch (error) {
		console.error('Registration error:', error);
		res.status(500).json({
			success: false,
			message: 'Internal server error during registration'
		});
	}
});

// User Login
app.post('/api/auth/login', [
	body('identifier').notEmpty().withMessage('Email or phone is required'),
	body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
	try {
		// Check for validation errors
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({
				success: false,
				message: 'Validation failed',
				errors: errors.array()
			});
		}

		const { identifier, password } = req.body;

		// Find user by email or phone
		const user = await UserAuthModel.findOne({
			$or: [
				{ email: identifier.toLowerCase() },
				{ phone: identifier }
			]
		});

		if (!user) {
			return res.status(401).json({
				success: false,
				message: 'Invalid credentials'
			});
		}

		// Check if user is active
		if (!user.isActive) {
			return res.status(401).json({
				success: false,
				message: 'Account is deactivated'
			});
		}

		// Verify password
		const isPasswordValid = await user.comparePassword(password);
		if (!isPasswordValid) {
			return res.status(401).json({
				success: false,
				message: 'Invalid credentials'
			});
		}

		// Update last login
		user.lastLogin = new Date();
		await user.save();

		// Generate JWT token
		const token = jwt.sign(
			{ userId: user._id, email: user.email },
			JWT_SECRET,
			{ expiresIn: '1d' }
		);

		res.json({
			success: true,
			message: 'Login successful',
			token,
			user: {
				id: user._id,
				name: user.name,
				email: user.email,
				phone: user.phone,
				lastLogin: user.lastLogin
			}
		});

	} catch (error) {
		console.error('Login error:', error);
		res.status(500).json({
			success: false,
			message: 'Internal server error during login'
		});
	}
});

// Get current user profile
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
	try {
		const user = await UserAuthModel.findById(req.user.userId);
		if (!user) {
			return res.status(404).json({
				success: false,
				message: 'User not found'
			});
		}

		res.json({
			success: true,
			user: {
				id: user._id,
				name: user.name,
				email: user.email,
				phone: user.phone,
				createdAt: user.createdAt,
				lastLogin: user.lastLogin
			}
		});

	} catch (error) {
		console.error('Profile fetch error:', error);
		res.status(500).json({
			success: false,
			message: 'Internal server error'
		});
	}
});

// Update user profile
app.put('/api/auth/profile', authenticateToken, [
	body('name').optional().trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters long'),
	body('email').optional().isEmail().normalizeEmail().withMessage('Please provide a valid email'),
	body('phone').optional().matches(/^[\+]?[1-9][\d]{0,15}$/).withMessage('Please provide a valid phone number')
], async (req, res) => {
	try {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({
				success: false,
				message: 'Validation failed',
				errors: errors.array()
			});
		}

		const { name, email, phone } = req.body;
		const updateData = {};

		if (name) updateData.name = name;
		if (email) updateData.email = email;
		if (phone) updateData.phone = phone;

		// Check for duplicate email/phone if updating
		if (email || phone) {
			const existingUser = await UserAuthModel.findOne({
				_id: { $ne: req.user.userId },
				$or: [
					...(email ? [{ email }] : []),
					...(phone ? [{ phone }] : [])
				]
			});

			if (existingUser) {
				return res.status(400).json({
					success: false,
					message: existingUser.email === email ? 'Email already in use' : 'Phone number already in use'
				});
			}
		}

		const user = await UserAuthModel.findByIdAndUpdate(
			req.user.userId,
			updateData,
			{ new: true, runValidators: true }
		);

		res.json({
			success: true,
			message: 'Profile updated successfully',
			user: {
				id: user._id,
				name: user.name,
				email: user.email,
				phone: user.phone,
				updatedAt: user.updatedAt
			}
		});

	} catch (error) {
		console.error('Profile update error:', error);
		res.status(500).json({
			success: false,
			message: 'Internal server error'
		});
	}
});

// --- Admin Authentication Routes ---

// Simple admin middleware
const authenticateAdmin = (req, res, next) => {
	const authHeader = req.headers['authorization'];
	const token = authHeader && authHeader.split(' ')[1];

	if (!token) {
		return res.status(401).json({
			success: false,
			message: 'Access token is required'
		});
	}

	try {
		const decoded = jwt.verify(token, JWT_SECRET);
		req.admin = decoded;
		next();
	} catch (error) {
		return res.status(403).json({
			success: false,
			message: 'Invalid or expired token'
		});
	}
};

// User authentication middleware
const authenticateUser = (req, res, next) => {
	const authHeader = req.headers['authorization'];
	const token = authHeader && authHeader.split(' ')[1];

	if (!token) {
		return res.status(401).json({
			success: false,
			message: 'Access token is required'
		});
	}

	try {
		const decoded = jwt.verify(token, JWT_SECRET);
		req.user = decoded;
		next();
	} catch (error) {
		return res.status(403).json({
			success: false,
			message: 'Invalid or expired token'
		});
	}
};

// Admin registration
app.post('/api/admin/register', [
	body('name').trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters long'),
	body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email'),
	body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
	body('department').trim().isLength({ min: 2 }).withMessage('Department is required'),
	body('position').trim().isLength({ min: 2 }).withMessage('Position is required')
], async (req, res) => {
	try {
		// Check for validation errors
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({
				success: false,
				message: 'Validation failed',
				errors: errors.array()
			});
		}

		const { name, email, password, department, position } = req.body;

		// Check if admin already exists
		const existingAdmin = await AdminAuthModel.findOne({ email: email.toLowerCase() });
		if (existingAdmin) {
			return res.status(400).json({
				success: false,
				message: 'Admin with this email already exists'
			});
		}

		// Create new admin
		const admin = new AdminAuthModel({
			name,
			email: email.toLowerCase(),
			password,
			department,
			position
		});

		await admin.save();

		// Generate JWT token
		const token = jwt.sign(
			{ 
				id: admin._id, 
				email: admin.email, 
				isAdmin: true 
			},
			JWT_SECRET,
			{ expiresIn: '24h' }
		);

		res.status(201).json({
			success: true,
			message: 'Admin registered successfully',
			token,
			admin: {
				id: admin._id,
				name: admin.name,
				email: admin.email,
				department: admin.department,
				position: admin.position,
				createdAt: admin.createdAt
			}
		});

	} catch (error) {
		console.error('Admin registration error:', error);
		res.status(500).json({
			success: false,
			message: 'Server error during registration'
		});
	}
});

// Admin login
app.post('/api/admin/login', async (req, res) => {
	try {
		const { email, password } = req.body;

		if (!email || !password) {
			return res.status(400).json({ 
				success: false, 
				message: 'Email and password required' 
			});
		}

		// Find admin
		const admin = await AdminAuthModel.findOne({ email: email.toLowerCase() });
		if (!admin) {
			return res.status(401).json({ 
				success: false, 
				message: 'Invalid credentials' 
			});
		}

		// Check password
		const isValid = await admin.comparePassword(password);
		if (!isValid) {
			return res.status(401).json({ 
				success: false, 
				message: 'Invalid credentials' 
			});
		}

		// Update last login
		admin.lastLogin = new Date();
		await admin.save();

		// Create token
		const token = jwt.sign(
			{ 
				id: admin._id, 
				email: admin.email, 
				isAdmin: true 
			},
			JWT_SECRET,
			{ expiresIn: '24h' }
		);

		res.json({
			success: true,
			message: 'Login successful',
			token,
			admin: {
				id: admin._id,
				name: admin.name,
				email: admin.email,
				department: admin.department,
				position: admin.position
			}
		});

	} catch (error) {
		console.error('Admin login error:', error);
		res.status(500).json({ 
			success: false, 
			message: 'Server error' 
		});
	}
});

// Get current admin profile
app.get('/api/admin/profile', authenticateAdmin, async (req, res) => {
	try {
		const admin = await AdminAuthModel.findById(req.admin.id).select('-password');
		if (!admin) {
			return res.status(404).json({
				success: false,
				message: 'Admin not found'
			});
		}
		res.json({ success: true, admin });
	} catch (error) {
		console.error('Admin profile fetch error:', error);
		res.status(500).json({
			success: false,
			message: 'Server error'
		});
	}
});

// Admin logout endpoint
app.post('/api/admin/logout', authenticateAdmin, async (req, res) => {
	try {
		// In a production app, you might want to maintain a blacklist of tokens
		// or store tokens in a database with expiration
		res.json({ success: true, message: 'Admin logged out successfully' });
	} catch (error) {
		console.error('Admin logout error:', error);
		res.status(500).json({ success: false, message: 'Server error' });
	}
});

// User logout endpoint
app.post('/api/auth/logout', async (req, res) => {
	try {
		// In a production app, you might want to maintain a blacklist of tokens
		// or store tokens in a database with expiration
		res.json({ success: true, message: 'User logged out successfully' });
	} catch (error) {
		console.error('User logout error:', error);
		res.status(500).json({ success: false, message: 'Server error' });
	}
});

// Get all tickets for admin (client-side filtering)
app.get('/api/admin/tickets', authenticateAdmin, async (req, res) => {
	try {
		// Get admin information to check department
		const admin = await AdminAuthModel.findById(req.admin.id);
		if (!admin) {
			return res.status(404).json({
				success: false,
				message: 'Admin not found'
			});
		}

		// Fetch ALL tickets - no server-side filtering
		const tickets = await TicketModel.find({})
			.populate('askerUserId', 'name email phone')
			.sort({ createdAt: -1 })
			.select('-__v');

		res.json({
			success: true,
			tickets,
			adminDepartment: admin.department
		});

	} catch (error) {
		console.error('Fetch admin tickets error:', error);
		res.status(500).json({
			success: false,
			message: 'Server error while fetching tickets'
		});
	}
});

// Update ticket status (admin only)
app.put('/api/admin/tickets/:ticketId', authenticateAdmin, async (req, res) => {
	try {
		const { ticketId } = req.params;
		const { status, adminNotes } = req.body;

		// Validate status
		const validStatuses = ['pending', 'in_progress', 'resolved', 'closed'];
		if (status && !validStatuses.includes(status)) {
			return res.status(400).json({
				success: false,
				message: 'Invalid status. Must be one of: pending, in_progress, resolved, closed'
			});
		}

		// Get admin information
		const admin = await AdminAuthModel.findById(req.admin.id);
		if (!admin) {
			return res.status(404).json({
				success: false,
				message: 'Admin not found'
			});
		}

		// Find and update ticket
		const updateData = {};
		if (status) updateData.status = status;
		if (adminNotes !== undefined) updateData.adminNotes = adminNotes;
		updateData.updatedAt = Date.now();

		const ticket = await TicketModel.findOneAndUpdate(
			{ ticketId: ticketId },
			updateData,
			{ new: true }
		);

		if (!ticket) {
			return res.status(404).json({
				success: false,
				message: 'Ticket not found'
			});
		}

		res.json({
			success: true,
			message: 'Ticket updated successfully',
			ticket
		});

	} catch (error) {
		console.error('Update ticket error:', error);
		res.status(500).json({
			success: false,
			message: 'Server error while updating ticket'
		});
	}
});

// Create ticket endpoint
app.post('/api/tickets/create', authenticateUser, async (req, res) => {
	try {
		const { message, departmentDirectedTo, urgency, location } = req.body;
		
		// Validate required fields
		if (!message || !departmentDirectedTo || !urgency || !location) {
			return res.status(400).json({
				success: false,
				message: 'Missing required fields: message, departmentDirectedTo, urgency, location'
			});
		}

		// Get user information
		console.log('Token payload:', req.user); // Debug log
		const user = await UserAuthModel.findById(req.user.userId);
		if (!user) {
			console.log('User not found with ID:', req.user.userId); // Debug log
			return res.status(404).json({
				success: false,
				message: 'User not found'
			});
		}

		// Create new ticket
		const ticket = new TicketModel({
			askerName: user.name,
			askerUserId: user._id,
			departmentDirectedTo,
			message,
			urgency,
			location: {
				coordinates: {
					latitude: location.latitude,
					longitude: location.longitude
				},
				address: location.address || ''
			}
		});

		await ticket.save();

		res.json({
			success: true,
			message: 'Ticket created successfully',
			ticket: {
				ticketId: ticket.ticketId,
				askerName: ticket.askerName,
				departmentDirectedTo: ticket.departmentDirectedTo,
				urgency: ticket.urgency,
				status: ticket.status,
				createdAt: ticket.createdAt
			}
		});

	} catch (error) {
		console.error('Ticket creation error:', error);
		res.status(500).json({
			success: false,
			message: 'Server error while creating ticket'
		});
	}
});

// Get user's tickets
app.get('/api/tickets/user', authenticateUser, async (req, res) => {
	try {
		const tickets = await TicketModel.find({ askerUserId: req.user.userId })
			.sort({ createdAt: -1 })
			.select('-askerUserId -__v');

		res.json({
			success: true,
			tickets
		});

	} catch (error) {
		console.error('Fetch user tickets error:', error);
		res.status(500).json({
			success: false,
			message: 'Server error while fetching tickets'
		});
	}
});

// Get ticket by ID
app.get('/api/tickets/:ticketId', authenticateUser, async (req, res) => {
	try {
		const { ticketId } = req.params;
		
		const ticket = await TicketModel.findOne({ 
			ticketId: ticketId,
			askerUserId: req.user.userId 
		}).select('-askerUserId -__v');

		if (!ticket) {
			return res.status(404).json({
				success: false,
				message: 'Ticket not found'
			});
		}

		res.json({
			success: true,
			ticket
		});

	} catch (error) {
		console.error('Fetch ticket error:', error);
		res.status(500).json({
			success: false,
			message: 'Server error while fetching ticket'
		});
	}
});

// Create default admin (for testing)
app.post('/api/admin/create-default', async (req, res) => {
	try {
		// Check if admin already exists
		const existingAdmin = await AdminAuthModel.findOne({ email: 'admin@upchaar.com' });
		if (existingAdmin) {
			return res.json({ 
				success: true, 
				message: 'Default admin already exists',
				credentials: {
					email: 'admin@upchaar.com',
					password: 'admin123'
				}
			});
		}

		// Create default admin
		const admin = new AdminAuthModel({
			name: 'System Admin',
			email: 'admin@upchaar.com',
			password: 'admin123',
			department: 'IT',
			position: 'Administrator'
		});

		await admin.save();

		res.json({
			success: true,
			message: 'Default admin created',
			credentials: {
				email: 'admin@upchaar.com',
				password: 'admin123'
			}
		});

	} catch (error) {
		console.error('Create admin error:', error);
		res.status(500).json({ 
			success: false, 
			message: 'Server error' 
		});
	}
});

// Frontend Routes
// Root path serves Main Page.html
app.get('/', (req, res) => {
	res.sendFile(path.join(frontendDir, 'Map Page.html'));
});

app.get('/admin-dashboard', (req, res) => {
	res.sendFile(path.join(frontendDir, 'Admin dashboard.html'));
});
app.get('/admin-login', (req, res) => {
	res.sendFile(path.join(frontendDir, 'Admin Login.html'));
});
app.get('/mainpage', (req, res) => {
	res.sendFile(path.join(frontendDir, 'mainpage.html'));
});
app.get('/mappage', (req, res) => {
	res.sendFile(path.join(frontendDir, 'Map Page.html'));
});
app.get('/track', (req, res) => {
	res.sendFile(path.join(frontendDir, 'Track.html'));
});
app.get('/user-dashboard', (req, res) => {
	res.sendFile(path.join(frontendDir, 'User Dashboard.html'));
});
app.get('/user-login', (req, res) => {
	res.sendFile(path.join(frontendDir, 'User Login.html'));
});

app.listen(PORT, () => {
	console.log(`Server is running on port ${PORT}`);
});
