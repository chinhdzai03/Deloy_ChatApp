const JWT = require('jsonwebtoken');
var User = require('../models/user.model');
const streamServer = require('../stream');

const handleRefreshToken = async (req, res) => {

    console.log('Someone refreshing');

    const cookies = req.cookies;
    if (!cookies?.jwt) {
        return res.status(401).send("No JWT cookies");
    }

    const refreshToken = cookies.jwt;

    // console.log(refreshToken);

    const existingUser = await User.findOne({ refreshToken: refreshToken });
    if (!existingUser) {
        return res.status(403).send("Invalid refresh token");
    }

    // evaluate jwt 
    JWT.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET,
        async (err, decoded) => {
            if (err || existingUser.username !== decoded.UserInfo.username)
                return res.status(403).send("Error verifying jwt || Token maybe expired");

            const username = existingUser.username;
            const userId = existingUser._id;
            const fullname = existingUser.fullname;
            const email = existingUser.email;
            const image = existingUser.image || `https://getstream.io/random_png/?name=${username}`;

            const newAccessToken = JWT.sign(
                {
                    "UserInfo": {
                        "username": username,
                        "userId": userId,
                        "email": email,
                        "fullname": fullname,
                    }
                },
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn: '8h' }
            );

            // get user's stream token
            const streamToken = await streamServer.createToken(username);

            return res.status(200).json({
                username, userId, fullname, email, accessToken: newAccessToken, streamToken, image
            });
        }
    );
}

module.exports = { handleRefreshToken }