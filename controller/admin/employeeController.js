const asyncHandler = require('express-async-handler');
const throwError = require('../../utils/throwError');
const bcrypt = require('bcrypt');
const {
  uploadBuffer,
  getFileUrl,
  deleteFile,
  getFileStream
} = require('../../utils/wasabi');
const path = require('path');
const archiver = require('archiver');
const formatDate = require('../../utils/formatDate');
const User = require('../../model/userModel');
const Employee = require('../../model/employeeModel');
const Loan = require('../../model/loanModel');
const mongoose = require('mongoose');

const { employeePages } = require('../../constants');

const addEmployee = asyncHandler(async (req, res) => {
  const {
    email,
    password,
    name,
    nik,
    age,
    phone,
    address,
    employment_type,
    religion,
    height,
    weight,
    number_of_children,
    place_of_birth,
    date_of_birth,
    status,
    bank_account_number,
    emergency_contact_number,
    position,
    blood_type,
    start_date,
    end_date,
    pages = []
  } = req.body || {};

  if (
    !email ||
    !password ||
    !name ||
    !phone ||
    !nik ||
    !employment_type ||
    !position
  ) {
    throwError('Field wajib belum lengkap', 400);
  }

  if (!email.endsWith('@soilab.id')) {
    throwError('Email harus menggunakan domain @soilab.id', 400);
  }

  const existing = await User.findOne({ email });
  if (existing) {
    throwError('Email sudah terdaftar', 400);
  }

  // validasi pages
  if (!Array.isArray(pages)) {
    throwError('Pages harus berupa array', 400);
  }

  const normalizedPages = pages.map((p) => String(p).toLowerCase());
  const invalidPages = normalizedPages.filter(
    (p) => !employeePages.includes(p)
  );

  if (invalidPages.length) {
    throwError(`Pages tidak valid: ${invalidPages.join(', ')}`, 400);
  }

  // 1️⃣ create USER
  const hashedPassword = await bcrypt.hash(password, 10);

  const user = await User.create({
    email,
    name,
    phone,
    password: hashedPassword,
    role: 'karyawan',
    oauthProvider: 'local',
    emailVerified: true
  });

  // 2️⃣ create EMPLOYEE
  const employee = await Employee.create({
    user: user._id,
    name,
    nik,
    age,
    phone,
    address,
    employment_type,
    religion,
    height,
    weight,
    number_of_children,
    place_of_birth,
    date_of_birth,
    status,
    bank_account_number,
    emergency_contact_number,
    position,
    blood_type,
    start_date,
    end_date,
    pages: normalizedPages
  });

  res.status(201).json({
    message: 'Karyawan berhasil ditambahkan',
    data: employee
  });
});

const updateEmployeePages = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { pages = [] } = req.body;

  if (!Array.isArray(pages)) {
    throwError('Pages harus berupa array', 400);
  }

  const normalizedPages = pages.map((p) => String(p).toLowerCase());

  const invalidPages = normalizedPages.filter(
    (p) => !employeePages.includes(p)
  );

  if (invalidPages.length) {
    throwError(`Pages tidak valid: ${invalidPages.join(', ')}`, 400);
  }

  const employee = await Employee.findById(id);
  if (!employee) {
    throwError('Karyawan tidak ditemukan', 404);
  }

  employee.pages = normalizedPages;
  await employee.save();

  res.json({
    message: 'Akses halaman berhasil diperbarui',
    data: employee.pages
  });
});

const getEmployees = asyncHandler(async (req, res) => {
  const mode = req.query.mode || 'paging';
  const limit = Math.min(parseInt(req.query.limit) || 10, 50);
  const { name, nik, employment_type, position, search, sort } = req.query;

  const filter = {};
  if (name) filter.name = { $regex: name, $options: 'i' };
  if (nik) filter.nik = { $regex: nik, $options: 'i' };
  if (employment_type) filter.employment_type = employment_type;
  if (position) filter.position = position;
  if (search) {
    filter.$or = [
      { name: { $regex: search, $options: 'i' } },
      { nik: { $regex: search, $options: 'i' } },
      { phone: { $regex: search, $options: 'i' } }
    ];
  }

  let sortOption = { createdAt: -1 };
  if (sort) {
    const [f, o] = sort.split(':');
    sortOption = { [f]: o === 'asc' ? 1 : -1 };
  }

  const baseQuery = Employee.find(filter)
    .select('nik name phone position address employment_type')
    .populate('user', 'email');

  if (mode === 'paging') {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const skip = (page - 1) * limit;

    const totalItems = await Employee.countDocuments(filter);
    const data = await baseQuery
      .skip(skip)
      .limit(limit)
      .sort(sortOption)
      .lean();

    return res.json({
      page,
      limit,
      totalItems,
      totalPages: Math.ceil(totalItems / limit),
      sort: sortOption,
      data
    });
  }

  if (mode === 'cursor') {
    if (req.query.cursor)
      filter.createdAt = { $lt: new Date(req.query.cursor) };
    const rows = await baseQuery
      .sort(sortOption)
      .limit(limit + 1)
      .lean();

    const hasMore = rows.length > limit;
    const data = hasMore ? rows.slice(0, limit) : rows;

    return res.json({
      sort: sortOption,
      data,
      nextCursor: hasMore ? data[data.length - 1].createdAt : null,
      hasMore
    });
  }

  throwError('mode pagination tidak valid', 400);
});

const getEmployee = asyncHandler(async (req, res) => {
  const employee = await Employee.findById(req.params.id)
    .populate('user', 'email')
    .exec();

  if (!employee) throwError('Data karyawan tidak ada!', 400);

  const docsEntries = await Promise.all(
    Object.entries(employee.documents || {}).map(async ([key, value]) => {
      if (value && value.key) {
        return [
          key,
          {
            ...(value.toObject?.() || value),
            url: await getFileUrl(value.key, 300, 'inline')
          }
        ];
      }
      return null;
    })
  );

  const docsWithUrl = Object.fromEntries(docsEntries.filter(Boolean));

  res.status(200).json({
    ...employee.toObject(),
    documents: docsWithUrl
  });
});

const removeEmployee = asyncHandler(async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const employee = await Employee.findById(req.params.id).session(session);
    if (!employee) throwError('Data karyawan tidak ada!', 404);

    // 1️⃣ hapus dokumen di storage
    if (employee.documents) {
      for (const value of Object.values(employee.documents)) {
        if (value?.key) {
          await deleteFile(value.key);
        }
      }
    }

    // 2️⃣ lepas relasi loan
    await Loan.updateMany(
      { employee: employee._id },
      { $set: { employee: null } },
      { session }
    );

    // 3️⃣ hapus employee
    await employee.deleteOne({ session });

    // 4️⃣ hapus user (HARD DELETE)
    if (employee.user) {
      await User.findByIdAndDelete(employee.user, { session });
    }

    await session.commitTransaction();

    res.status(200).json({
      message: 'Karyawan dan akun berhasil dihapus'
    });
  } catch (err) {
    await session.abortTransaction();
    console.error(err);
    throwError('Gagal menghapus karyawan', 400);
  } finally {
    session.endSession();
  }
});

const updateEmployee = asyncHandler(async (req, res) => {
  const employee = await Employee.findById(req.params.id);
  if (!employee) throwError('Karyawan tidak ditemukan!', 404);

  const employeeFields = [
    'name',
    'nik',
    'age',
    'phone',
    'address',
    'employment_type',
    'religion',
    'height',
    'weight',
    'number_of_children',
    'place_of_birth',
    'date_of_birth',
    'status',
    'bank_account_number',
    'emergency_contact_number',
    'position',
    'blood_type',
    'start_date',
    'end_date'
  ];

  for (const field of employeeFields) {
    if (req.body[field] !== undefined) {
      employee[field] = req.body[field];
    }
  }

  if (employee.user) {
    const userUpdate = {};

    if (req.body.name) userUpdate.name = req.body.name;
    if (req.body.phone) userUpdate.phone = req.body.phone;

    if (Object.keys(userUpdate).length) {
      await User.findByIdAndUpdate(employee.user, userUpdate);
    }
  }

  if (req.files) {
    for (const field of [
      'ktp',
      'asuransi',
      'mcu',
      'keterangan_sehat',
      'kelakuan_baik',
      'vaksinasi'
    ]) {
      if (req.files[field]) {
        const file = req.files[field][0];
        const ext = path.extname(file.originalname);

        if (employee.documents?.[field]?.key) {
          await deleteFile(employee.documents[field].key);
        }

        const key = `karyawan/${employee._id}/${field}_${formatDate()}${ext}`;
        await uploadBuffer(key, file.buffer, {
          contentType: file.mimetype
        });

        employee.documents[field] = {
          key,
          contentType: file.mimetype,
          size: file.size,
          uploadedAt: new Date()
        };
      }
    }
  }

  await employee.save();

  res.status(200).json({
    message: 'Data karyawan berhasil diperbarui',
    data: employee
  });
});

const downloadEmployeeDocs = asyncHandler(async (req, res) => {
  const employee = await Employee.findById(req.params.id);
  if (!employee) throwError('Data karyawan tidak ada!', 404);

  const docs = employee.documents || {};
  const docEntries = Object.entries(docs).filter(([_, v]) => v?.key);

  if (docEntries.length === 0) {
    return res.status(404).json({ message: 'Tidak ada dokumen untuk diunduh' });
  }

  res.setHeader('Content-Type', 'application/zip');
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="${employee.name}-docs.zip"`
  );

  const archive = archiver('zip', { zlib: { level: 9 } });
  archive.pipe(res);

  for (const [docName, docValue] of docEntries) {
    const stream = await getFileStream(docValue.key);
    const ext = path.extname(docValue.key) || '';
    archive.append(stream, { name: `${docName}${ext}` });
  }

  await archive.finalize();
});

const resetEmployeePassword = asyncHandler(async (req, res) => {
  if (req.user.role !== 'admin') {
    throwError('Akses ditolak. Hanya admin yang diizinkan.', 403);
  }

  const { id } = req.params;
  const { newPassword } = req.body;

  if (!newPassword) {
    throwError('Password baru wajib diisi', 400);
  }

  if (newPassword.length < 8 || !/\d/.test(newPassword)) {
    throwError('Password minimal 8 karakter dan mengandung angka', 400);
  }

  const employee = await Employee.findById(id);
  if (!employee || !employee.user) {
    throwError('Karyawan tidak ditemukan', 404);
  }

  const hashedPassword = await bcrypt.hash(newPassword, 10);

  await User.findByIdAndUpdate(employee.user, {
    password: hashedPassword
  });

  res.status(200).json({
    message: 'Password karyawan berhasil di-reset'
  });
});

const updateEmployeeEmail = asyncHandler(async (req, res) => {
  if (req.user.role !== 'admin') {
    throwError('Akses ditolak', 403);
  }

  const { id } = req.params;
  const { email } = req.body;

  if (!email) {
    throwError('Email wajib diisi', 400);
  }

  if (!email.endsWith('@soilab.id')) {
    throwError('Email harus menggunakan domain @soilab.id', 400);
  }

  const employee = await Employee.findById(id);
  if (!employee || !employee.user) {
    throwError('Karyawan tidak ditemukan', 404);
  }

  const emailUsed = await User.findOne({
    email,
    _id: { $ne: employee.user }
  });

  if (emailUsed) {
    throwError('Email sudah digunakan', 400);
  }

  await User.findByIdAndUpdate(employee.user, {
    email
  });

  res.json({
    message: 'Email karyawan berhasil diperbarui'
  });
});

module.exports = {
  addEmployee,
  getEmployee,
  getEmployees,
  removeEmployee,
  updateEmployee,
  updateEmployeePages,
  resetEmployeePassword,
  updateEmployeeEmail,
  downloadEmployeeDocs
};
