package com.api.gateway.jwt.token.model;

import org.springframework.stereotype.Service;

import com.api.gateway.jwt.token.error.UserNotFoundException;

@Service
public class UserServiceImpl implements UserService {
	private UserRepository userRepository;

	public UserServiceImpl(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	public void saveUser(User user) {
		userRepository.save(user);
	}

	public User getUserByNameAndPassword(String name, String password) throws UserNotFoundException {
		User user = userRepository.findByUserNameAndPassword(name, password);
		if (user == null) {
			throw new UserNotFoundException("Invalid id and password");
		}
		return user;
	}

	public User getUserByName(String name) throws UserNotFoundException {
		User user = userRepository.findByUserName(name);
		if (user == null) {
			throw new UserNotFoundException("Invalid id and password");
		}
		return user;
	}

}
