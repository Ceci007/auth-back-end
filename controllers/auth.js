import User from '../models/user'
import { hashPassword, comparePassword } from '../utils/auth'

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