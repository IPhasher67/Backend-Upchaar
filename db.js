const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const env = require("dotenv").config();

// Connect to MongoDB
mongoose.connect(process.env.connectionString || "mongodb://localhost:27017/upchaar", {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log("Connected to database");
}).catch((err) => {
    console.log("Database connection error:", err);
});

// User Authentication Schema
const userAuthSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, "Name is required"],
        trim: true,
        minlength: [2, "Name must be at least 2 characters long"]
    },
    email: {
        type: String,
        required: [true, "Email is required"],
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,})+$/, "Please enter a valid email"]
    },
    phone: {
        type: String,
        required: [true, "Phone number is required"],
        unique: true,
        trim: true,
        match: [/^[\+]?[1-9][\d]{0,15}$/, "Please enter a valid phone number"]
    },
    password: {
        type: String,
        required: [true, "Password is required"],
        minlength: [6, "Password must be at least 6 characters long"]
    },
    isActive: {
        type: Boolean,
        default: true
    },
    lastLogin: {
        type: Date,
        default: null
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Hash password before saving
userAuthSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(12);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Update updatedAt field before saving
userAuthSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

// Method to compare password
userAuthSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// Method to get user without sensitive data
userAuthSchema.methods.toJSON = function() {
    const user = this.toObject();
    delete user.password;
    return user;
};

// Create User model
const UserAuthModel = mongoose.model("UserAuth", userAuthSchema);

// Admin Authentication Schema
const adminAuthSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, "Name is required"],
        trim: true,
        minlength: [2, "Name must be at least 2 characters long"]
    },
    email: {
        type: String,
        required: [true, "Email is required"],
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,})+$/, "Please enter a valid email"]
    },
    password: {
        type: String,
        required: [true, "Password is required"],
        minlength: [6, "Password must be at least 6 characters long"]
    },
    department: {
        type: String,
        required: [true, "Department is required"],
        trim: true
    },
    position: {
        type: String,
        required: [true, "Position is required"],
        trim: true
    },
    isActive: {
        type: Boolean,
        default: true
    },
    lastLogin: {
        type: Date,
        default: null
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Hash password before saving
adminAuthSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(12);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Update updatedAt field before saving
adminAuthSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

// Method to compare password
adminAuthSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// Method to get admin without sensitive data
adminAuthSchema.methods.toJSON = function() {
    const admin = this.toObject();
    delete admin.password;
    return admin;
};

// Create Admin model
const AdminAuthModel = mongoose.model("AdminAuth", adminAuthSchema);

// Ticket Schema for issue tracking
const ticketSchema = new mongoose.Schema({
    ticketId: {
        type: String,
        unique: true
    },
    askerName: {
        type: String,
        required: true
    },
    askerUserId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'UserAuth',
        required: true
    },
    departmentDirectedTo: {
        type: String,
        required: true,
        enum: [
            'District Administration',
            'Police Department', 
            'District Judiciary',
            'Public Works Department (PWD)',
            'Health Department',
            'Education Department',
            'Social Welfare Department',
            'Food and Civil Supplies Department',
            'Agriculture Department',
            'Rural Development Agency',
            'Animal Husbandry and Fisheries Department',
            'Industries and Commerce Department'
        ]
    },
    message: {
        type: String,
        required: true
    },
    urgency: {
        type: String,
        required: true,
        enum: ['low', 'medium', 'high']
    },
    location: {
        coordinates: {
            latitude: {
                type: Number,
                required: true
            },
            longitude: {
                type: Number,
                required: true
            }
        },
        address: {
            type: String,
            default: ''
        }
    },
    status: {
        type: String,
        default: 'pending',
        enum: ['pending', 'in_progress', 'resolved', 'closed']
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    },
    adminNotes: {
        type: String,
        default: ''
    }
}, {
    timestamps: true
});

// Generate unique ticket ID
ticketSchema.pre('save', async function(next) {
    if (!this.ticketId) {
        const departmentCode = {
            'Water Department': 'WTR',
            'Electricity Department': 'ELC',
            'Road Department': 'RD',
            'Waste Management': 'WST',
            'Health Department': 'HLT',
            'General': 'GEN'
        };
        
        const code = departmentCode[this.departmentDirectedTo] || 'GEN';
        const randomNum = Math.floor(1000 + Math.random() * 9000);
        const randomChar = String.fromCharCode(65 + Math.floor(Math.random() * 26));
        this.ticketId = `${code}-${randomNum}${randomChar}`;
    }
    this.updatedAt = Date.now();
    next();
});

// Create Ticket model
const TicketModel = mongoose.model("Ticket", ticketSchema);

module.exports = {
    UserAuthModel,
    AdminAuthModel,
    TicketModel,
    mongoose
};