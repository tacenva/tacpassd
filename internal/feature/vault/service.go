package vault

import (
	"errors"

	"github.com/tacenva/database"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/vaultaccess"
)

var ErrForbidden = errors.New("forbidden")

type Service struct {
	tacenvaRawDB *database.RawDB
	vaService    *vaultaccess.Service
}

func NewService(
	tacenvaRawDB *database.RawDB,
	vaService *vaultaccess.Service,
) *Service {
	return &Service{
		tacenvaRawDB: tacenvaRawDB,
		vaService:    vaService,
	}
}

// Create membuat record baru di vault.
// ID dibuat otomatis oleh RawDB.
func (s *Service) CreateRecord(
	authUser *entity.User,
	vaultID string,
	data []byte,
) (string, error) {
	if err := s.checkAccess(authUser, vaultID); err != nil {
		return "", err
	}

	fileDB, err := s.tacenvaRawDB.File(vaultID)
	if err != nil {
		return "", err
	}

	return fileDB.Insert(data)
}

// Get mengambil satu record berdasarkan ID.
func (s *Service) GetRecord(
	authUser *entity.User,
	vaultID string,
	recordID string,
) ([]byte, error) {
	if err := s.checkAccess(authUser, vaultID); err != nil {
		return nil, err
	}

	fileDB, err := s.tacenvaRawDB.File(vaultID)
	if err != nil {
		return nil, err
	}

	return fileDB.Find(recordID)
}

// GetAll mengambil seluruh record dalam vault.
func (s *Service) GetAllRecord(
	authUser *entity.User,
	vaultID string,
) (map[string][]byte, error) {
	if err := s.checkAccess(authUser, vaultID); err != nil {
		return nil, err
	}

	fileDB, err := s.tacenvaRawDB.File(vaultID)
	if err != nil {
		return nil, err
	}

	return fileDB.FindAll()
}

// Update mengubah data record berdasarkan ID.
func (s *Service) UpdateRecord(
	authUser *entity.User,
	vaultID string,
	recordID string,
	data []byte,
) error {
	if err := s.checkAccess(authUser, vaultID); err != nil {
		return err
	}

	fileDB, err := s.tacenvaRawDB.File(vaultID)
	if err != nil {
		return err
	}

	return fileDB.Update(
		recordID,
		data,
	)
}

// Delete menghapus record berdasarkan ID.
func (s *Service) DeleteRecord(
	authUser *entity.User,
	vaultID string,
	recordID string,
) error {
	if err := s.checkAccess(authUser, vaultID); err != nil {
		return err
	}

	fileDB, err := s.tacenvaRawDB.File(vaultID)
	if err != nil {
		return err
	}

	return fileDB.Delete(recordID)
}

func (s *Service) checkAccess(
	authUser *entity.User,
	vaultID string,
) error {
	if authUser == nil {
		return ErrForbidden
	}

	isAccessible, err := s.vaService.IsVaultAccesible(
		vaultID,
		authUser.PermissionID,
	)
	if err != nil {
		return err
	}

	if !isAccessible {
		return ErrForbidden
	}

	return nil
}
