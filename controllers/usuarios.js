const { request, response } = require("express");
const bcryptjs = require("bcryptjs");

const Usuario = require("../models/usuario");

const usuariosGet = async (req = request, res = response) => {
  const { limite = 5, desde = 0 } = req.query;
  const query = { estado: true };

  //Queremos que ambas peticiones (listado de usuarios y total) se lanzen al mismo tiempo
  const [total, usuarios] = await Promise.all([
    //En estos metodos se puede mandar un objeto para filtrar los resultados
    Usuario.countDocuments(query),
    Usuario.find(query).skip(Number(desde)).limit(Number(limite)),
  ]);

  res.json({ total, usuarios });
};

const usuariosPut = async (req, res = response) => {
  //Para extraer parametros de segmento
  const { id } = req.params;
  const { _id, password, google, correo, ...resto } = req.body;

  //TODO: validar contra base de datos
  if (password) {
    const salt = bcryptjs.genSaltSync();
    resto.password = bcryptjs.hashSync(password, salt);
  }

  const usuario = await Usuario.findByIdAndUpdate(id, resto);

  res.json(usuario);
};

const usuariosPost = async (req, res = response) => {
  //Se revisan middlewares de la ruta

  const { nombre, correo, password, rol } = req.body;
  const usuario = new Usuario({ nombre, correo, password, rol });

  //Cifrar contrasena
  const salt = bcryptjs.genSaltSync();
  usuario.password = bcryptjs.hashSync(password, salt);

  //Guardar en DB
  await usuario.save();

  res.json({ msg: "post API - controlador", usuario });
};

const usuariosDelete = async (req, res = response) => {
  const { id } = req.params;

  //Borrado fisico
  // const usuario = await Usuario.findByIdAndDelete(id);

  //Borrado por estado
  const usuario = await Usuario.findByIdAndUpdate(id, { estado: false });

  res.json({ usuario });
};

const usuariosPatch = (req, res = response) => {
  res.json({ msg: "patch API - controlador" });
};

module.exports = {
  usuariosGet,
  usuariosPut,
  usuariosPost,
  usuariosDelete,
  usuariosPatch,
};
