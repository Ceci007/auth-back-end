import User from '../models/user'
import { hashPassword, comparePassword } from '../utils/auth'
import jwt from 'jsonwebtoken'
import AWS from 'aws-sdk'
import { nanoid } from 'nanoid'

const awsConfig = {
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION,
  apiVersion: process.env.AWS_API_VERSION
}

const SES = new AWS.SES(awsConfig);

export const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if(!name) 
      return res.status(400).send("Please enter your name");
    if(!password || password.length < 6) 
      return res.status(400).send("Please enter a valid password");

    let userExist = await User.findOne({ email }).exec();
    if(userExist)
      return res.status(400).send("Email is taken");

    const hashedPassword = await hashPassword(password);

    const user = new User({
      name, 
      email, 
      password: hashedPassword
    })
    await user.save();

    return res.json({ ok: true });
  } catch(err) {
    console.log(err);
    return res.status(400).send('Error, try again later');
  }
}

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).exec();

    if(!user)
      return res.status(400).send('No user found');
    
    const match = await comparePassword(password, user.password);

    if(!match)
      return res.status(400).send('Wrong email or password');

    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d"
    });

    user.password = undefined;
    res.cookie("token", token, {
      httpOnly: true,
      // secure: true
    });

    res.json(user);
  } catch(err) {
    console.log(err);
    return res.status(400).send('Error, try again later');
  }
}

export const logout = async (req, res) => {
  try {
    res.clearCookie('token');
    return res.json({ message: 'Logout successful'});
  } catch(err) {
    console.log(err);
    return res.status(400).send('Error, try again later');
  }
}

export const currentUser = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password').exec();
    console.log('current user', user);
    return res.json({ ok: true });
  } catch(err) {
    console.log(err);
  }
}

export const sendEmail = async (req, res) => {
  const params = {
    Source: process.env.EMAIL_FROM,
    Destination: {
      ToAddresses: ['cecibenitezca@gmail.com']
    },
    ReplyToAddresses: [process.env.EMAIL_FROM],
    Message: {
      Body: {
        Html: {
          Charset: 'UTF-8',
          Data: `
            <html>
              <h1>Reset password</h1>
              <p>Please use the following link to reset your password</p>
            </html>
          `
        }
      },
      Subject: {
        Charset: 'UTF-8',
        Data: 'Reset password'
      }
    }
  };

  const emailSent = SES.sendEmail(params).promise();

  emailSent.then((data) => {
    console.log(data);
    res.json({ ok: true });
  })
  .catch(err => {
    console.log(err);
  });
}

export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const shortCode = nanoid(6).toUpperCase();
    const user = await User.findOneAndUpdate(
      { email }, 
      { passwordResetCode: shortCode }
    );

    if(!user) return res.status(400).send('User not found');

    const params = {
      Source: process.env.EMAIL_FROM,
      Destination: {
        ToAddresses: [email]
      },
      Message: {
        Body: {
          Html: {
            Charset: 'UTF-8',
            Data: `
              <html>
                <head>
                  <style>
                    @import url('https://fonts.googleapis.com/css2?family=Raleway:ital,wght@0,100;0,200;0,300;0,400;0,500;0,600;0,700;1,300&display=swap');

                    .email-container {
                      display: block;
                      margin: 10px auto;
                      background: #fff;
                      box-sizing: border-box;
                      border: 1px solid #dedede;
                      border-radius: 10px;
                      padding: 30px 20px;
                    }

                    h2 {
                      color: #448aff;
                      font-family: 'Raleway', sans-serif;
                      font-size: 16px;
                    }

                    p {
                      color: #3e3e3e;
                      font-family: 'Raleway', sans-serif;
                      font-size: 16px;
                      font-weight: 300;
                    }

                    span {
                      color: #3e3e3e;
                      font-family: 'Raleway', sans-serif;
                      font-size: 16px;
                      font-weight: 700;
                    }

                    a,
                    a:link,
                    a:visited {
                      color: #fff;
                      padding: 10px 30px;
                      font-family: 'Raleway', sans-serif;
                      font-size: 14px;
                      font-weight: 600;
                      text-decoration: none;
                      background: #448aff;
                      border-radius: 3px;
                    }
                  </style>
                </head>
                <body>
                  <div class="email-container">
                    <h2>Reset Password</h2>
                    <p>Use this code to reset your password</p>
                    <p><span>${shortCode}</span></p>
                    <a>Edemy</a>
                  </div>
                </body>
              </html>
            `
          }
        },
        Subject: {
          Charset: 'UTF-8',
          Data: 'Reset Password'
        }
      },
    };

    const emailSent = SES.sendEmail(params).promise();
    emailSent.then((data) => {
      console.log(data);
      res.json({ ok: true });
    }).catch((err) => {
      console.log(err);
    });
  } catch(err) {
    console.log(err);
  }
}

export const resetPassword = async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;

    const hashedPassword = await hashPassword(newPassword);

    const user = User.findOneAndUpdate({
      email,
      passwordResetCode: code,
    }, {
      password: hashedPassword,
      passwordResetCode: '',
    }).exec();

    res.json({ ok: true });
  } catch(err) {
    console.log(err);
    return res.status(400).send('Error, try again later');
  }
}