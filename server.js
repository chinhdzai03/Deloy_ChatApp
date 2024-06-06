const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const cookieParser = require('cookie-parser');

require('dotenv').config();

const { app, server } = require('./socket');

app.use(cors({
    origin: 'https://localhost:3000'
}));

// middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// mongodb atlas connect
const uri = process.env.MONGODB_URI;
mongoose.connect(uri, { dbName: 'chat-webapp' });
const connection = mongoose.connection;
connection.once('open', () => {
    console.log("MongoDB Cloud connection established successfully");
})

// routing
const registerRouter = require('./routes/register.router');
const authRouter = require('./routes/auth.router');
const logoutRouter = require('./routes/logout.router');
const refreshTokenRouter = require('./routes/refreshToken.router');
const userRouter = require('./routes/user.router');
const groupRouter = require('./routes/group.router');
const callRouter = require('./routes/call.router');
const chatRouter = require('./routes/chat.router');

const verifyJWT = require('./middlewares/verifyJWT');

app.use('/api/register', registerRouter);
app.use('/api/auth', authRouter);
app.use('/api/refresh', refreshTokenRouter);
app.use('/api/logout', logoutRouter);
app.use('/api/user', verifyJWT, userRouter);
app.use('/api/group', verifyJWT, groupRouter);
app.use('/api/call', verifyJWT, callRouter);
app.use('/api/chat', verifyJWT, chatRouter);

const _dirname = path.dirname("")
const buildPath = path.join(_dirname, "./client/build");

app.use(express.static(buildPath))

app.get(/^\/(?!api).*/, function (req, res) {
    res.sendFile(
        path.join(__dirname, "./client/build/index.html"),
        function (err) {
            if (err) {
                res.status(500).send(err);
            }
        }
    );
})

// server host
const port = process.env.PORT;
const ip = process.env.IP;

server.listen(port, ip, () => {
    console.log(`Server is running at ${ip}:${port}`);
})

