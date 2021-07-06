export const register = (req, res) => {
  console.log(req.body);
  res.json('register user endpoint, response from controller');
}