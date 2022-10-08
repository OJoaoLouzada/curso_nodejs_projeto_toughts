const User = require('../models/User')
const bcrypt = require('bcryptjs')

module.exports = class AuthController {
  static login(req, res) {
    res.render('auth/login')
  }

  static async loginPost(req, res) {
    const {email, password} = req.body

    //Validação se usuário existe
    const user = await User.findOne({where: {email: email}})

    if(!user) {
      req.flash('message', 'Usuário não encontrado!')
      res.render('auth/login')

      return
    }

    // Validação se a senha é correta
    const passwordMatch = bcrypt.compareSync(password, user.password)

    if(!passwordMatch) {
      req.flash('message', 'Senha inválida!')
      res.render('auth/login')

      return
    }

    req.session.userid = user.id

    req.flash('message', 'Login realizado com sucesso!')

    //Salvar sessão para redirecionar e manter logado
    req.session.save(() => {
      res.redirect('/')
    })
  }

  static register(req, res) {
    res.render('auth/register')
  }

  static async registerPost(req, res) {
    const {name, email, password, confirmpassword} = req.body

    //Validação da confirmação de senha
    if(password != confirmpassword) {
      req.flash('message', 'A senha e a confirmação da senha estão diferentes. Tente novamente!')
      res.render('auth/register')

      return
    }

    //Validação se o usuário existe
    const checkIfUserExists = await User.findOne({where: {email: email}})
    if(checkIfUserExists) {
      req.flash('message', 'Esse e-mail já está cadastrado!')
      res.render('auth/register')

      return
    }

    //Criar uma senha
    //Salt serve para acrescentar caracteres à string de senha criptografada para dificultar hacking
    const salt = bcrypt.genSaltSync(10)
    const hashedPassword = bcrypt.hashSync(password, salt)

    const user = {
      name,
      email,
      password: hashedPassword
    }

    try {
      const createdUser = await User.create(user)

      //Inicializar a sessão ao se cadastrar
      req.session.userid = createdUser.id

      req.flash('message', 'Cadastro realizado com sucesso!')

      //Salvar sessão para redirecionar e manter logado
      req.session.save(() => {
        res.redirect('/')
      })
    } catch(err) {
      console.log(err)
    }
    
  }

  static logout(req, res) {
    req.session.destroy()
    res.redirect('/login')
  }
}