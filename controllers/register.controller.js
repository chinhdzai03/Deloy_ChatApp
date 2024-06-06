const bcrypt = require('bcrypt');
const JWT = require('jsonwebtoken');
var User = require('../models/user.model');
const streamServer = require('../stream');

const handleRegister = async (req, res) => {
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;

    let existingUser = await User.findOne({ username });
    if (existingUser) {
        console.log("Username duplicated");
        return res.status(409).json({ taken: 0 });
    } else {
        existingUser = await User.findOne({ email });
        if (existingUser) {
            console.log("Email duplicated");
            return res.status(409).json({ taken: 1 });
        }

        // Generate a salt
        bcrypt.genSalt(10, (err, salt) => {
            if (err) {
                return res.status(500).json("Error generating salt:" + err);
            }

            // Hash the password using the generated salt
            bcrypt.hash(password, salt, (err, hashedPassword) => {
                if (err) {
                    return res.status(500).json("Error hashing password: " + err);
                }
                else {
                    // console.log('Hashed Password:', hashedPassword);
                    const refreshToken = JWT.sign(
                        {
                            "UserInfo": {
                                "username": username,
                                "email": email,
                            }
                        },
                        process.env.REFRESH_TOKEN_SECRET,
                        { expiresIn: '7d' }
                    );

                    const newUser = new User({
                        username: username, email: email, password: hashedPassword, refreshToken,
                        image: `https://getstream.io/random_svg/?id=oliver&name=${username}`
                    });
                    newUser.save()
                        .then(async () => {
                            console.log("Registered");
                            const accessToken = JWT.sign(
                                {
                                    "UserInfo": {
                                        "username": newUser.username,
                                        "userId": newUser._id,
                                        "email": newUser.email,
                                    }
                                },
                                process.env.ACCESS_TOKEN_SECRET,
                                { expiresIn: '8h' }
                            );

                            // sent refresh token as http cookie, last for 1d
                            res.cookie('jwt', refreshToken, { httpOnly: true, sameSite: 'Strict', secure: true, maxAge: 24 * 60 * 60 * 1000 });

                            // get user's stream token
                            const streamToken = await streamServer.createToken(username);

                            return res.status(200).json({
                                accessToken: accessToken,
                                userId: newUser._id,
                                email: newUser.email,
                                username: newUser.username,
                                image: newUser.image,
                                streamToken: streamToken
                            });
                        })
                        .catch(err => {
                            console.log(err);
                            return res.status(400).json(err)
                        });
                }
            });
        });
    }
}
module.exports = { handleRegister };